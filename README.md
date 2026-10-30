# Subenum

> **Orchestrated Subdomain Enumeration Pipeline**  
> *Passive Discovery &rarr; Active Bruteforce &rarr; HTTP/DNS Probing &rarr; Web Crawling &rarr; Structured Reporting*

`subenum` is an automated, modular subdomain enumeration and reconnaissance pipeline designed for bug hunters and penetration testers. It aggregates results across passive sources, optional high-speed active DNS bruteforce, live HTTP/DNS resolution, and web crawling to produce clean, actionable asset inventories.

Missing third-party tools or omitted API keys are gracefully skipped without aborting the scan.

---

## Architecture & Workflow

```text
                  +-----------------------------------+
                  |           Target Domain           |
                  +-----------------+-----------------+
                                    |
            +-----------------------v-----------------------+
            | 1. Passive Enumeration (Parallel Workers)     |
            |    crt.sh, Subfinder, Amass, Assetfinder,     |
            |    Waybackurls, GAU, Cero, CTFR, Gungnir,     |
            |    GitHub-Subdomains, Censys, Shodan, Crobat, |
            |    AnalyticsRelationships                     |
            +-----------------------+-----------------------+
                                    |
            +-----------------------v-----------------------+
            | 2. Active DNS Recon (Optional: --active)      |
            |    dnsvalidator (Fresh resolver generation)   |
            |    puredns (Massive wordlist bruteforce)      |
            |    shuffledns & puredns resolve               |
            +-----------------------+-----------------------+
                                    |
            +-----------------------v-----------------------+
            | 3. Probing & DNS Record Enrichment           |
            |    Wildcard DNS detection                     |
            |    httpx (Status, Title, Tech, Server)        |
            |    dnsx (A, AAAA, CNAME, MX, NS, PTR, SOA)    |
            +-----------------------+-----------------------+
                                    |
            +-----------------------v-----------------------+
            | 4. Web Spidering / Crawling                   |
            |    gospider (Crawls live web roots, JS,       |
            |    robots.txt, and sitemaps for new hosts)    |
            +-----------------------+-----------------------+
                                    |
            +-----------------------v-----------------------+
            | 5. Final Output & Categorized Reporting       |
            |    [LIVE] vs [NOT LIVE] Hosts                 |
            |    Raw artifacts in <target>_recon/           |
            +-----------------------------------------------+
```

---

## Features

- **Multi-Source Passive Enumeration**: Queries Certificate Transparency (crt.sh, Cero, Gungnir), search engines, archives (Wayback, AlienVault/GAU), APIs (Shodan, Censys, GitHub), and Google Analytics ID correlation (`analyticsrelationships`).
- **Resilient & Fault-Tolerant**: Every tool is executed within an isolated process group with strict timeouts. Missing binaries or unconfigured API keys are skipped and logged—never breaking the workflow.
- **Active Bruteforcing & Resolving**: Generates fresh, trusted resolvers via `dnsvalidator` and utilizes `massdns` powered tools (`puredns`, `shuffledns`) to resolve large wordlists rapidly.
- **Liveness Verification**: Leverages ProjectDiscovery's `httpx` to probe live HTTP/HTTPS endpoints and collect web metadata (status codes, titles, tech stack). Automatically falls back to high-concurrency socket DNS resolution if `httpx` is not present.
- **DNS Record Extraction**: Dumps full DNS resource records using `dnsx` into `dnsx_records.txt`.
- **In-Depth Crawling**: Passes discovered live web endpoints into `gospider` to uncover hidden endpoints and nested subdomains from JavaScript files and sitemaps.
- **Clean Output Organization**: Produces a consolidated report with distinct `[LIVE]` and `[NOT LIVE]` sections alongside timestamped metadata.

---

## Supported Tools

| Phase | Tool | Purpose | Source / Type |
| :--- | :--- | :--- | :--- |
| **Passive** | `crt.sh` | Certificate Transparency search | Built-in HTTPS API query |
| **Passive** | `subfinder` | Passive subdomain discovery | Go binary (ProjectDiscovery) |
| **Passive** | `amass` | OSINT & network mapping | Go binary (OWASP) |
| **Passive** | `assetfinder` | Passive domain discovery | Go binary (tomnomnom) |
| **Passive** | `waybackurls` | Fetch URLs from Wayback Machine | Go binary (tomnomnom) |
| **Passive** | `gau` | Fetch URLs from AlienVault, Wayback, Common Crawl | Go binary (lc) |
| **Passive** | `cero` | Rapid TLS certificate scraping | Go binary (glebarez) |
| **Passive** | `ctfr` | Certificate Transparency Log monitor | Python script |
| **Passive** | `gungnir` | Real-time CT log monitor | Go binary (g0ldencybersec) |
| **Passive** | `github-subdomains` | Subdomain search on GitHub repositories | Go binary (gwen001) |
| **Passive** | `censys-subdomain-finder`| Query Censys dataset | Python script |
| **Passive** | `shodomain` | Shodan passive subdomain discovery | Python script |
| **Passive** | `crobat` | Project Crobat API query | Go binary (cgboal) |
| **Passive** | `analyticsrelationships`| Reverse Google Analytics / Tag IDs | Go binary (Josue87) |
| **Active** | `dnsvalidator` | Compile reliable, unfiltered DNS resolvers | Python package |
| **Active** | `puredns` | High-speed DNS bruteforce & resolving (MassDNS) | Go binary (d3mondev) |
| **Active** | `shuffledns` | Wildcard-aware DNS resolver | Go binary (ProjectDiscovery) |
| **Probing** | `httpx` | Fast multi-purpose HTTP probing | Go binary (ProjectDiscovery) |
| **Probing** | `dnsx` | Fast multi-purpose DNS toolkit | Go binary (ProjectDiscovery) |
| **Crawl** | `gospider` | Fast web spider & crawler | Go binary (jaeles-project) |

---

## Installation

### Prerequisites

- **OS**: Linux / macOS / WSL (Windows Subsystem for Linux)
- **Go**: 1.21 or higher ([go.dev/dl](https://go.dev/dl/))
- **Python**: 3.9+ with `pip`
- **Compiler / Build Tools**: `gcc` / `cc`, `make`, `git`, `curl`

### Automated Installation (`install.sh`)

Use the included installer script to automatically download Go tools, clone Python utilities, install dependencies, and download starter DNS wordlists:

```bash
git clone https://github.com/MRMcyber/Subenum.git
cd Subenum

# Make script executable and run installer
chmod +x install.sh
./install.sh
```

Ensure your Go binary path is included in your `PATH`:

```bash
export PATH=$PATH:$(go env GOPATH)/bin
# Or add to ~/.bashrc:
echo 'export PATH=$PATH:$(go env GOPATH)/bin' >> ~/.bashrc && source ~/.bashrc
```

#### Installer Environment Variables:
- `UPDATE=1 ./install.sh` &mdash; Force re-download and update of all tools and wordlists.
- `TOOLS_DIR=/custom/path ./install.sh` &mdash; Specify a custom directory for cloned scripts and wordlists (defaults to `~/Tools`).

### Python Dependencies

If running manually or setting up a virtual environment:

```bash
pip install -r requirements.txt
```

---

## Configuration & API Keys

Passive discovery functions without API keys, but configuring them substantially improves yield:

```bash
# GitHub Token (for github-subdomains)
export GITHUB_TOKEN="ghp_yourTokenHere"

# Shodan API Key (for shodomain)
export SHODAN_API_KEY="yourShodanKeyHere"

# Censys API Credentials (for censys-subdomain-finder)
export CENSYS_API_ID="yourCensysAppId"
export CENSYS_API_SECRET="yourCensysSecret"
```

For `subfinder` and `amass`, configure their respective standard configuration files:
- Subfinder: `~/.config/subfinder/provider-config.yaml`
- Amass: `~/.config/amass/config.yaml`

---

## Usage

### 1. Basic Passive Scan
Runs all available passive sources, probes for liveness, runs `dnsx` record enumeration, and crawls live hosts:

```bash
python3 subenum.py example.com
```

### 2. Active Enumeration (Bruteforce & Resolving)
Includes `dnsvalidator` resolver compilation and `puredns` DNS bruteforcing:

```bash
python3 subenum.py example.com --active -w ~/Tools/subdomains.txt
```

### 3. Supply Pre-generated Resolvers
```bash
python3 subenum.py example.com --active -w ~/Tools/subdomains.txt -r /path/to/resolvers.txt
```

### 4. Provide API Keys via Flags
```bash
python3 subenum.py example.com --github-tokens tokens.txt --shodan-key <API_KEY>
```

### 5. Skip Specific Modules or Crawling
```bash
# Skip specific sources (comma-separated)
python3 subenum.py example.com --skip amass,censys

# Disable gospider crawling
python3 subenum.py example.com --no-crawl
```

### Command-Line Arguments Reference

| Argument | Description | Default |
| :--- | :--- | :--- |
| `domain` | Target domain to enumerate (e.g. `example.com`) | *Required* |
| `-o, --outdir` | Output directory where reports and recon files are stored | `.` |
| `--active` | Enable active DNS bruteforcing and resolution stages | `False` |
| `-w, --wordlist` | Path to DNS wordlist for `puredns bruteforce` | `None` |
| `-r, --resolvers` | Path to trusted DNS resolvers list | Auto-generated via `dnsvalidator` |
| `--tools-dir` | Directory where helper scripts (`ctfr.py`, `shodomain.py`) are located | `~/Tools` |
| `--github-tokens`| GitHub personal access token or path to tokens file | `$GITHUB_TOKEN` |
| `--shodan-key` | Shodan API key | `$SHODAN_API_KEY` |
| `-j, --jobs` | Number of concurrent passive enumeration tasks | `6` |
| `--timeout` | Timeout in seconds for individual tool execution | `600` |
| `--probe-timeout`| Timeout in seconds for HTTP probing | `1800` |
| `--crawl-timeout`| Timeout in seconds for web crawler | `1200` |
| `--gungnir-time` | Duration in seconds to stream live CT logs with `gungnir` | `60` |
| `--no-crawl` | Skip `gospider` crawling stage | `False` |
| `--skip` | Comma-separated list of tool names to skip | `""` |

---

## Output Structure

Upon completion, `subenum` organizes all data cleanly:

```text
.
├── example_subdomains.txt          <-- Consolidated final report
└── example_recon/                  <-- Recon artifacts & tool logs
    ├── all_subdomains.txt          <-- All deduplicated candidate subdomains
    ├── websites.txt                <-- Live HTTP/HTTPS endpoints
    ├── webs_info.txt               <-- HTTP response data (status codes, titles, servers)
    ├── dnsx_records.txt            <-- Complete DNS records (A, AAAA, CNAME, MX, etc.)
    ├── urls.txt                    <-- Discovered URLs from crawler
    └── raw/                        <-- Raw output dumps from each tool
        ├── amass.txt
        ├── subfinder.txt
        ├── crtsh.txt
        ├── puredns_bruteforce.out
        └── ...
```

### Sample Report (`example_subdomains.txt`)

```text
# Target    : example.com
# Generated : 2026-10-30 02:14:33 UTC
# Total     : 42  (live: 28, not live: 14)
# Live means: answered over HTTP(S) (httpx)
# Sources   : crtsh, subfinder, assetfinder, waybackurls, gau

[LIVE]
admin.example.com
api.example.com
app.example.com
portal.example.com
www.example.com

[NOT LIVE]
dev.example.com
staging-old.example.com
test.example.com
```

---

## Disclaimer

> **IMPORTANT**: This tool is designed strictly for authorized security assessments, penetration tests, and bug bounty programs where explicit permission has been granted. Unauthorized scanning, probing, or attacking targets without prior consent is illegal. The author assumes no liability for misuse or damage caused by this software.

---

## License

This project is licensed under the [MIT License](LICENSE).
