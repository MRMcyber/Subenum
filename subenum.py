#!/usr/bin/env python3
"""
subenum.py - orchestrated subdomain enumeration (passive -> optional active -> probe -> crawl)

Only run this against targets you are authorized to test.

Usage:
    python3 subenum.py example.com
    python3 subenum.py example.com --active -w ~/Tools/subdomains.txt
    python3 subenum.py example.com --github-tokens tokens.txt --shodan-key KEY

Result:
    <label>_subdomains.txt   e.g. google_subdomains.txt  (LIVE and NOT LIVE sections)
    <label>_recon/           raw per-tool output, webs_info.txt, dnsx_records.txt, urls.txt, ...

"Live" = answered over HTTP(S) according to ProjectDiscovery httpx.
If httpx is missing, the script falls back to "resolves in DNS".
Missing tools / missing API keys are skipped and reported, never fatal.
"""
import argparse
import concurrent.futures as cf
import datetime as dt
import json
import os
import random
import re
import shlex
import shutil
import signal
import socket
import string
import subprocess
import sys
import time
import urllib.request
from pathlib import Path
from urllib.parse import urlparse

DOMAIN_RE = re.compile(r"^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")


class Skip(Exception):
    """Raised when a source can't run (missing binary, key, script...)."""


def log(msg):
    print(msg, file=sys.stderr, flush=True)


def need(*bins):
    for b in bins:
        if not shutil.which(b):
            raise Skip(f"{b} not installed")


# --------------------------------------------------------------------------- #
# process helpers
# --------------------------------------------------------------------------- #
def _kill(p, sig):
    try:
        os.killpg(os.getpgid(p.pid), sig)
    except (ProcessLookupError, PermissionError):
        pass


def run(cmd, timeout, stdin_text=None, cwd=None):
    """Run list (no shell) or str (shell, for pipelines). On timeout the whole
    process group is killed and whatever was printed so far is returned."""
    p = subprocess.Popen(
        cmd,
        shell=isinstance(cmd, str),
        stdin=subprocess.PIPE if stdin_text is not None else subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        errors="replace",
        start_new_session=True,
        cwd=cwd,
    )
    try:
        out, err = p.communicate(stdin_text, timeout=timeout)
    except subprocess.TimeoutExpired:
        _kill(p, signal.SIGTERM)
        try:
            out, err = p.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            _kill(p, signal.SIGKILL)
            out, err = p.communicate()
        return out or "", err or "", None
    return out, err, p.returncode


class Ctx:
    def __init__(self, domain, args, work):
        self.d = domain
        self.a = args
        self.work = work
        self.raw = work / "raw"
        self.current = {domain}
        self.pat = re.compile(
            r"(?<![a-z0-9_\-.@])((?:[a-z0-9_*\-]+\.)*" + re.escape(domain) + r")(?![a-z0-9_\-]|\.[a-z0-9])"
        )

    def run(self, cmd, timeout=None, stdin_text=None, cwd=None):
        out, err, rc = run(cmd, timeout or self.a.timeout, stdin_text, cwd)
        if rc not in (0, None) and not out.strip():
            raise RuntimeError(f"exit {rc}: {err.strip()[-200:]}")
        return out

    def extract(self, text):
        found = set()
        for m in self.pat.findall(text.lower()):
            h = m.strip(".")
            while h.startswith("*."):
                h = h[2:]
            if "*" in h or len(h) > 253:
                continue
            found.add(h)
        return found


def read_if(path):
    p = Path(path)
    return p.read_text(errors="replace") if p.is_file() else ""


def find_script(c, names):
    for n in names:
        p = shutil.which(n)
        if p:
            return p
    base = Path(c.a.tools_dir).expanduser()
    cands = []
    for n in names:
        cands += [base / n] + list(base.glob(f"*/{n}")) + [Path.cwd() / n]
    for p in cands:
        if p.is_file():
            return str(p)
    raise Skip(f"{names[0]} not found (use --tools-dir)")


def py_cmd(script, *args):
    return ([sys.executable, script] if script.endswith(".py") else [script]) + list(args)


# --------------------------------------------------------------------------- #
# passive sources - each returns raw text
# --------------------------------------------------------------------------- #
def s_crtsh(c):  # built-in crt.sh query, no extra tool needed
    url = f"https://crt.sh/?q=%25.{c.d}&output=json"
    last = None
    for i in range(3):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0 subenum"})
            with urllib.request.urlopen(req, timeout=120) as r:
                data = json.loads(r.read().decode())
            return "\n".join(x.get("name_value", "") for x in data)
        except Exception as e:  # noqa: BLE001
            last = e
            time.sleep(5 * (i + 1))
    raise RuntimeError(f"crt.sh failed: {last}")


def s_amass(c):
    need("amass")
    return c.run(["amass", "enum", "-passive", "-d", c.d])


def s_subfinder(c):
    need("subfinder")
    return c.run(["subfinder", "-d", c.d, "-all", "-silent"])


def s_assetfinder(c):
    need("assetfinder")
    return c.run(["assetfinder", c.d])


def s_waybackurls(c):
    need("waybackurls", "unfurl")
    return c.run(f"echo {shlex.quote(c.d)} | waybackurls | unfurl -u domains")


def s_gau(c):
    need("gau", "unfurl")
    return c.run(f"gau --subs {shlex.quote(c.d)} | unfurl -u domains")


def s_cero(c):
    need("cero")
    return c.run(["cero", c.d])


def s_ctfr(c):
    script = find_script(c, ["ctfr.py", "ctfr"])
    return c.run(py_cmd(script, "-d", c.d), cwd=str(Path(script).parent))


def s_gungnir(c):
    need("gungnir")
    f = c.work / "gungnir_domains.txt"
    f.write_text(c.d + "\n")
    # gungnir is a live CT-log monitor: listen for a fixed window, keep what it printed
    return c.run(["gungnir", "-r", str(f)], timeout=c.a.gungnir_time)


def s_github(c):
    need("github-subdomains")
    tok = c.a.github_tokens or os.environ.get("GITHUB_TOKEN")
    if not tok:
        raise Skip("no --github-tokens / GITHUB_TOKEN")
    if not Path(tok).is_file():
        f = c.work / "gh_tokens.txt"
        f.write_text(tok + "\n")
        f.chmod(0o600)
        tok = str(f)
    outf = c.raw / "github-subdomains.out"
    text = c.run(["github-subdomains", "-d", c.d, "-t", tok, "-o", str(outf)])
    return text + "\n" + read_if(outf)


def s_censys(c):
    if not (os.environ.get("CENSYS_API_ID") and os.environ.get("CENSYS_API_SECRET")):
        raise Skip("CENSYS_API_ID / CENSYS_API_SECRET not set")
    script = find_script(c, ["censys-subdomain-finder.py"])
    return c.run(py_cmd(script, c.d), cwd=str(Path(script).parent))


def s_shodomain(c):
    key = c.a.shodan_key or os.environ.get("SHODAN_API_KEY")
    if not key:
        raise Skip("no --shodan-key / SHODAN_API_KEY")
    script = find_script(c, ["shodomain.py"])
    return c.run(py_cmd(script, key, c.d), cwd=str(Path(script).parent))


def s_crobat(c):
    need("crobat")
    return c.run(["crobat", "-s", c.d])


PASSIVE = [
    ("crtsh", s_crtsh),
    ("amass", s_amass),
    ("subfinder", s_subfinder),
    ("assetfinder", s_assetfinder),
    ("waybackurls", s_waybackurls),
    ("gau", s_gau),
    ("cero", s_cero),
    ("ctfr", s_ctfr),
    ("gungnir", s_gungnir),
    ("github-subdomains", s_github),
    ("censys", s_censys),
    ("shodomain", s_shodomain),
    ("crobat", s_crobat),
]


def s_analytics(c):
    need("analyticsrelationships")
    return c.run("analyticsrelationships", stdin_text="\n".join(sorted(c.current)) + "\n")


# --------------------------------------------------------------------------- #
# active recon
# --------------------------------------------------------------------------- #
def ensure_resolvers(c):
    if c.a.resolvers:
        p = Path(c.a.resolvers).expanduser()
        if not p.is_file():
            raise Skip(f"resolvers file {p} not found")
        return str(p)
    need("dnsvalidator")
    out = c.work / "resolvers.txt"
    c.run(
        ["dnsvalidator", "-tL", "https://public-dns.info/nameservers.txt", "-threads", "200", "-o", str(out)],
        timeout=1800,
    )
    if not out.is_file() or not out.read_text().strip():
        raise RuntimeError("dnsvalidator produced no resolvers")
    return str(out)


def s_puredns_brute(c, res):
    need("puredns")
    if not c.a.wordlist:
        raise Skip("no --wordlist")
    wl = str(Path(c.a.wordlist).expanduser())
    outf = c.raw / "puredns_bruteforce.out"
    text = c.run(["puredns", "bruteforce", wl, c.d, "-r", res, "-w", str(outf), "-q"], timeout=3600)
    return text + "\n" + read_if(outf)


def s_shuffledns(c, res):
    need("shuffledns")
    inp = c.work / "all_subdomains.txt"
    inp.write_text("\n".join(sorted(c.current)) + "\n")
    return c.run(["shuffledns", "-d", c.d, "-list", str(inp), "-r", res, "-mode", "resolve", "-silent"], timeout=3600)


def s_puredns_resolve(c, res):
    need("puredns")
    inp = c.work / "all_subdomains.txt"
    inp.write_text("\n".join(sorted(c.current)) + "\n")
    outf = c.raw / "puredns_resolve.out"
    text = c.run(["puredns", "resolve", str(inp), "-r", res, "-w", str(outf), "-q"], timeout=3600)
    return text + "\n" + read_if(outf)


# --------------------------------------------------------------------------- #
# probing / crawling
# --------------------------------------------------------------------------- #
def is_pd_httpx():
    exe = shutil.which("httpx")
    if not exe:
        return False
    out, err, _ = run([exe, "-h"], 20)
    return "projectdiscovery" in (out + err).lower()


def probe_http(c, hosts):
    hosts = sorted(hosts)
    out = c.run(
        ["httpx", "-follow-host-redirects", "-random-agent", "-status-code", "-silent", "-retries", "2",
         "-title", "-web-server", "-tech-detect", "-location", "-nc"],
        timeout=c.a.probe_timeout,
        stdin_text="\n".join(hosts) + "\n",
    )
    live, urls, lines = set(), set(), []
    for line in out.splitlines():
        line = line.strip()
        if not line:
            continue
        tok = line.split()[0]
        h = urlparse(tok).hostname
        if h:
            live.add(h.lower())
            urls.add(tok)
        lines.append(line)
    return live & set(hosts), urls, lines


def probe_dns(hosts, workers=100):
    def ok(h):
        try:
            socket.getaddrinfo(h, None)
            return h
        except OSError:
            return None

    with cf.ThreadPoolExecutor(workers) as ex:
        return {h for h in ex.map(ok, sorted(hosts)) if h}


def wildcard(domain):
    label = "".join(random.choices(string.ascii_lowercase + string.digits, k=14))
    try:
        socket.getaddrinfo(f"{label}.{domain}", None)
        return True
    except OSError:
        return False


def crawl(c, urls):
    f = c.work / "websites.txt"
    f.write_text("\n".join(sorted(urls)) + "\n")
    out = c.run(
        ["gospider", "-S", str(f), "--js", "-t", "20", "-d", "2", "--sitemap", "--robots", "-w", "-r"],
        timeout=c.a.crawl_timeout,
    )
    (c.work / "urls.txt").write_text(out)
    hosts = set()
    for line in out.splitlines():
        if len(line) >= 2048:  # same as: sed '/^.\{2048\}./d'
            continue
        for m in re.findall(r"https?://[^\s\]\"'<>]+", line):
            h = urlparse(m).hostname
            if h:
                hosts |= c.extract(h)
    return hosts


# --------------------------------------------------------------------------- #
# driver
# --------------------------------------------------------------------------- #
def run_source(name, fn, c, *extra):
    t = time.time()
    try:
        text = fn(c, *extra)
        (c.raw / f"{name}.txt").write_text(text)
        found = c.extract(text)
        return name, found, f"{len(found)} hosts ({time.time() - t:.0f}s)"
    except Skip as e:
        return name, set(), f"skipped - {e}"
    except Exception as e:  # noqa: BLE001
        return name, set(), f"FAILED - {e}"


def write_report(path, domain, live, dead, sources, wc, mode):
    total = len(live) + len(dead)
    lines = [
        f"# Target    : {domain}",
        f"# Generated : {dt.datetime.now().astimezone().strftime('%Y-%m-%d %H:%M:%S %Z')}",
        f"# Total     : {total}  (live: {len(live)}, not live: {len(dead)})",
        f"# Live means: {mode}",
        f"# Sources   : {', '.join(sources) or 'none'}",
    ]
    if wc:
        lines.append("# WARNING   : wildcard DNS detected - DNS-based results may contain false positives")
    lines += ["", "[LIVE]", *sorted(live), "", "[NOT LIVE]", *sorted(dead), ""]
    Path(path).write_text("\n".join(lines))


def main():
    ap = argparse.ArgumentParser(description="Subdomain enumeration orchestrator (authorized targets only)")
    ap.add_argument("domain")
    ap.add_argument("-o", "--outdir", default=".", help="where the results are written (default: .)")
    ap.add_argument("--active", action="store_true", help="also run dnsvalidator/puredns/shuffledns")
    ap.add_argument("-w", "--wordlist", help="DNS wordlist for puredns bruteforce (use with --active)")
    ap.add_argument("-r", "--resolvers", help="resolvers file (default: generate with dnsvalidator)")
    ap.add_argument("--tools-dir", default="~/Tools", help="where ctfr.py, shodomain.py etc. live (default: ~/Tools)")
    ap.add_argument("--github-tokens", help="github token or tokens file (or GITHUB_TOKEN env)")
    ap.add_argument("--shodan-key", help="Shodan API key (or SHODAN_API_KEY env)")
    ap.add_argument("--timeout", type=int, default=600, help="per-tool timeout, seconds (default 600)")
    ap.add_argument("--gungnir-time", type=int, default=60, help="how long gungnir listens (default 60s)")
    ap.add_argument("--probe-timeout", type=int, default=1800)
    ap.add_argument("--crawl-timeout", type=int, default=1200)
    ap.add_argument("-j", "--jobs", type=int, default=6, help="parallel passive sources (default 6)")
    ap.add_argument("--no-crawl", action="store_true", help="skip the gospider crawling stage")
    ap.add_argument("--skip", default="", help="comma-separated source names to skip")
    args = ap.parse_args()

    domain = re.sub(r"^https?://", "", args.domain.strip().lower()).split("/")[0].strip(".")
    if not DOMAIN_RE.match(domain):
        ap.error(f"'{args.domain}' is not a valid domain")

    label = domain.split(".")[0]
    outdir = Path(args.outdir).expanduser()
    work = outdir / f"{label}_recon"
    (work / "raw").mkdir(parents=True, exist_ok=True)
    c = Ctx(domain, args, work)
    skip = {s.strip() for s in args.skip.split(",") if s.strip()}
    status, used = [], []

    def record(name, found, st):
        status.append((name, st))
        if found:
            used.append(name)
        log(f"  [{name:<22}] {st}")

    subs = {domain}

    # 1. passive ------------------------------------------------------------- #
    log(f"[*] Passive enumeration for {domain}")
    with cf.ThreadPoolExecutor(max_workers=max(1, args.jobs)) as ex:
        futs = [ex.submit(run_source, n, fn, c) for n, fn in PASSIVE if n not in skip]
        for f in cf.as_completed(futs):
            name, found, st = f.result()
            subs |= found
            record(name, found, st)
    c.current = set(subs)

    if "analyticsrelationships" not in skip:
        name, found, st = run_source("analyticsrelationships", s_analytics, c)
        subs |= found
        record(name, found, st)
        c.current = set(subs)

    # 2. active -------------------------------------------------------------- #
    if args.active:
        log("[*] Active recon")
        try:
            res = ensure_resolvers(c)
            for name, fn in (("puredns-bruteforce", s_puredns_brute), ("shuffledns", s_shuffledns),
                             ("puredns-resolve", s_puredns_resolve)):
                if name in skip:
                    continue
                n, found, st = run_source(name, fn, c, res)
                subs |= found
                c.current = set(subs)
                record(n, found, st)
        except Skip as e:
            record("active", set(), f"skipped - {e}")
        except Exception as e:  # noqa: BLE001
            record("active", set(), f"FAILED - {e}")

    (work / "all_subdomains.txt").write_text("\n".join(sorted(subs)) + "\n")
    log(f"[*] {len(subs)} unique candidates collected")

    # 3. probe --------------------------------------------------------------- #
    wc = wildcard(domain)
    if wc:
        log("[!] Wildcard DNS detected - DNS-only results are unreliable for this target")

    use_httpx = is_pd_httpx()
    web_lines = []
    if use_httpx:
        log("[*] Probing with httpx")
        live, urls, web_lines = probe_http(c, subs)
        mode = "answered over HTTP(S) (httpx)"
    else:
        log("[!] ProjectDiscovery httpx not found - falling back to DNS resolution for liveness")
        live = probe_dns(subs)
        urls = {f"https://{h}" for h in live}
        mode = "resolves in DNS (httpx missing)"

    if shutil.which("dnsx"):
        try:
            rec = c.run(
                ["dnsx", "-retry", "3", "-a", "-aaaa", "-cname", "-ns", "-ptr", "-mx", "-soa", "-resp", "-silent",
                 "-l", str(work / "all_subdomains.txt")]
            )
            (work / "dnsx_records.txt").write_text(rec)
            record("dnsx", set(), "records saved to dnsx_records.txt")
        except Exception as e:  # noqa: BLE001
            record("dnsx", set(), f"FAILED - {e}")
    else:
        record("dnsx", set(), "skipped - dnsx not installed")

    # 4. crawl --------------------------------------------------------------- #
    if not args.no_crawl:
        if not shutil.which("gospider"):
            record("gospider", set(), "skipped - gospider not installed")
        elif not urls:
            record("gospider", set(), "skipped - no live sites to crawl")
        else:
            log("[*] Crawling live sites with gospider")
            try:
                new = crawl(c, urls) - subs
                record("gospider", new, f"{len(new)} new hosts")
                if new:
                    subs |= new
                    if use_httpx:
                        l2, u2, w2 = probe_http(c, new)
                    else:
                        l2 = probe_dns(new)
                        u2, w2 = {f"https://{h}" for h in l2}, []
                    live |= l2
                    urls |= u2
                    web_lines += w2
            except Exception as e:  # noqa: BLE001
                record("gospider", set(), f"FAILED - {e}")

    if web_lines:
        (work / "webs_info.txt").write_text("\n".join(web_lines) + "\n")
    (work / "all_subdomains.txt").write_text("\n".join(sorted(subs)) + "\n")

    # 5. report -------------------------------------------------------------- #
    dead = subs - live
    out_file = outdir / f"{label}_subdomains.txt"
    write_report(out_file, domain, live, dead, used, wc, mode)

    log("\n[+] Done")
    log(f"    live: {len(live)}   not live: {len(dead)}   total: {len(subs)}")
    log(f"    raw tool output: {work}/")
    print(out_file)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        log("\n[!] interrupted")
        sys.exit(130)
