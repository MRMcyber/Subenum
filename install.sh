#!/usr/bin/env bash
# install.sh - installs every tool subenum.py can use.
#
#   ./install.sh            install anything missing
#   UPDATE=1 ./install.sh   reinstall / update everything
#   TOOLS_DIR=/opt/tools ./install.sh   change where scripts + wordlists go (default ~/Tools)
#
# Needs: go (1.21+), git, python3 + pip, make, a C compiler.
# A failed tool is reported at the end and never stops the rest.

set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TOOLS_DIR="${TOOLS_DIR:-$HOME/Tools}"
UPDATE="${UPDATE:-0}"
OK=(); FAIL=(); SKIP=()

ok()   { OK+=("$1");   printf '  [ok]    %s\n' "$1"; }
bad()  { FAIL+=("$1"); printf '  [FAIL]  %s\n' "$1"; }
skip() { SKIP+=("$1"); printf '  [skip]  %s (already installed, UPDATE=1 to refresh)\n' "$1"; }

# --- prerequisites ---------------------------------------------------------- #
missing=0
for b in git python3 make curl; do
  command -v "$b" >/dev/null 2>&1 || { echo "missing prerequisite: $b"; missing=1; }
done
command -v cc >/dev/null 2>&1 || command -v gcc >/dev/null 2>&1 || { echo "missing prerequisite: C compiler (gcc)"; missing=1; }
if ! command -v go >/dev/null 2>&1; then
  echo "missing prerequisite: go  (https://go.dev/dl/ - the apt version is often too old)"
  missing=1
fi
[ "$missing" -eq 1 ] && { echo "Install the above and re-run."; exit 1; }

GOBIN_DIR="$(go env GOBIN)"
[ -z "$GOBIN_DIR" ] && GOBIN_DIR="$(go env GOPATH)/bin"
mkdir -p "$TOOLS_DIR/wordlists"

# --- Go tools --------------------------------------------------------------- #
echo "[*] Go tools -> $GOBIN_DIR"
GO_TOOLS=(
  "amass|github.com/owasp-amass/amass/v4/...@master"
  "subfinder|github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
  "assetfinder|github.com/tomnomnom/assetfinder@latest"
  "waybackurls|github.com/tomnomnom/waybackurls@latest"
  "unfurl|github.com/tomnomnom/unfurl@latest"
  "gau|github.com/lc/gau/v2/cmd/gau@latest"
  "cero|github.com/glebarez/cero@latest"
  "gungnir|github.com/g0ldencybersec/gungnir/cmd/gungnir@latest"
  "github-subdomains|github.com/gwen001/github-subdomains@latest"
  "crobat|github.com/cgboal/sonarsearch/cmd/crobat@latest"
  "puredns|github.com/d3mondev/puredns/v2@latest"
  "shuffledns|github.com/projectdiscovery/shuffledns/cmd/shuffledns@latest"
  "httpx|github.com/projectdiscovery/httpx/cmd/httpx@latest"
  "dnsx|github.com/projectdiscovery/dnsx/cmd/dnsx@latest"
  "gospider|github.com/jaeles-project/gospider@latest"
  "analyticsrelationships|github.com/Josue87/analyticsrelationships@latest"
)
for entry in "${GO_TOOLS[@]}"; do
  name="${entry%%|*}"; pkg="${entry#*|}"
  if [ "$UPDATE" != "1" ] && { command -v "$name" >/dev/null 2>&1 || [ -x "$GOBIN_DIR/$name" ]; }; then
    skip "$name"; continue
  fi
  if go install "$pkg" >/dev/null 2>&1; then ok "$name"; else bad "$name  (go install $pkg)"; fi
done

# --- massdns (required by puredns) ------------------------------------------ #
echo "[*] massdns"
if [ "$UPDATE" != "1" ] && command -v massdns >/dev/null 2>&1; then
  skip "massdns"
else
  tmp="$(mktemp -d)"
  if git clone -q --depth 1 https://github.com/blechschmidt/massdns.git "$tmp/massdns" \
     && make -C "$tmp/massdns" >/dev/null 2>&1 \
     && mkdir -p "$GOBIN_DIR" && cp "$tmp/massdns/bin/massdns" "$GOBIN_DIR/massdns"; then
    ok "massdns"
  else
    bad "massdns  (build manually: https://github.com/blechschmidt/massdns)"
  fi
  rm -rf "$tmp"
fi

# --- Python packages -------------------------------------------------------- #
pip_install() {
  python3 -m pip install -q "$@" >/dev/null 2>&1 \
    || python3 -m pip install -q --break-system-packages "$@" >/dev/null 2>&1
}

echo "[*] Python packages (requirements.txt)"
if [ -f "$HERE/requirements.txt" ]; then
  while IFS= read -r line; do
    line="${line%%#*}"; line="$(echo "$line" | xargs)"
    [ -z "$line" ] && continue
    if pip_install "$line"; then ok "pip: $line"; else bad "pip: $line"; fi
  done < "$HERE/requirements.txt"
fi

# --- Python tools that are cloned, not packaged ------------------------------ #
echo "[*] Cloned Python tools -> $TOOLS_DIR"
clone_tool() {   # name url
  local name="$1" url="$2" dir="$TOOLS_DIR/$1"
  if [ -d "$dir/.git" ]; then
    [ "$UPDATE" = "1" ] && git -C "$dir" pull -q >/dev/null 2>&1
  elif ! git clone -q --depth 1 "$url" "$dir" >/dev/null 2>&1; then
    bad "$name  (git clone $url)"; return
  fi
  [ -f "$dir/requirements.txt" ] && pip_install -r "$dir/requirements.txt"
  ok "$name"
}
clone_tool ctfr                      https://github.com/UnaPibaGeek/ctfr.git
clone_tool censys-subdomain-finder   https://github.com/christophetd/censys-subdomain-finder.git
clone_tool Shodomain                 https://github.com/SmoZy92/Shodomain.git

# --- wordlists --------------------------------------------------------------- #
echo "[*] Wordlists -> $TOOLS_DIR/wordlists"
fetch() {   # name url
  local out="$TOOLS_DIR/wordlists/$1"
  if [ "$UPDATE" != "1" ] && [ -s "$out" ]; then skip "$1"; return; fi
  if curl -fsSL --retry 3 -o "$out" "$2"; then ok "$1"; else rm -f "$out"; bad "$1  ($2)"; fi
}
fetch best-dns-wordlist.txt https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt
fetch six2dez-subdomains.txt https://gist.githubusercontent.com/six2dez/a307a04a222fab5a57466c51e1569acf/raw
fetch jhaddix-all.txt        https://gist.githubusercontent.com/jhaddix/f64c97d0863a78454e44c2f7119c2a6a/raw
# default wordlist for:  python3 subenum.py target.com --active -w ~/Tools/subdomains.txt
[ -s "$TOOLS_DIR/wordlists/best-dns-wordlist.txt" ] && cp -f "$TOOLS_DIR/wordlists/best-dns-wordlist.txt" "$TOOLS_DIR/subdomains.txt"

# --- summary ----------------------------------------------------------------- #
echo
echo "installed: ${#OK[@]}   already present: ${#SKIP[@]}   failed: ${#FAIL[@]}"
if [ "${#FAIL[@]}" -gt 0 ]; then
  echo "Failed:"; printf '  - %s\n' "${FAIL[@]}"
fi
case ":$PATH:" in
  *":$GOBIN_DIR:"*) ;;
  *) echo; echo "Add Go binaries to PATH:  echo 'export PATH=\$PATH:$GOBIN_DIR' >> ~/.bashrc && source ~/.bashrc" ;;
esac
cat <<EOF

Optional API keys (more passive results):
  subfinder / amass   ~/.config/subfinder/provider-config.yaml, ~/.config/amass/config.yaml
  github-subdomains   export GITHUB_TOKEN=...   (or --github-tokens file)
  Shodan              export SHODAN_API_KEY=...
  Censys              export CENSYS_API_ID=... CENSYS_API_SECRET=...
EOF
