#!/usr/bin/env bash
# bootstrap-v2go-ultra.sh
# One-shot, safe, automated setup for V2Ray aggregator + GitHub Actions.
# - Creates Files/main.go and go.mod
# - Creates .github/workflows/Update-V2Ray-Configs.yml
# - Ensures Go toolchain (installs portable Go if missing)
# - Builds and runs aggregator
# - Produces All_Configs_Sub.txt, All_Configs_base64_Sub.txt, Splitted-By-Protocol/, Base64/, output/
# - Designed to run cleanly in GitHub Codespaces or Ubuntu shell

set -Eeuo pipefail

# --------------- helpers ---------------
log() { echo "[$(date -u +'%Y-%m-%dT%H:%M:%SZ')] $*"; }
fail() { echo "::error::$*"; exit 1; }

trap 'ec=$?; echo "::error::bootstrap failed with code $ec"; exit $ec' ERR

ROOT_DIR="$(pwd)"
FILES_DIR="${ROOT_DIR}/Files"
WF_DIR="${ROOT_DIR}/.github/workflows"
OUTPUT_DIR="${ROOT_DIR}/output"
PROTO_DIR="${ROOT_DIR}/Splitted-By-Protocol"
BASE64_DIR="${ROOT_DIR}/Base64"

GO_MIN_VER="1.21"
GO_LOCAL_DIR="${HOME}/.local/go"
GO_LOCAL_BIN="${GO_LOCAL_DIR}/bin/go"

ensure_go() {
  if command -v go >/dev/null 2>&1; then
    log "Go found: $(go version)"
    return 0
  fi
  log "Go not found. Installing a portable Go toolchain locally..."
  mkdir -p "${HOME}/.local"
  # Choose Go 1.22.x portable build
  GO_VER="1.22.5"
  if [[ "$(uname -m)" == "aarch64" || "$(uname -m)" == "arm64" ]]; then
    GO_TAR="go${GO_VER}.linux-arm64.tar.gz"
  else
    GO_TAR="go${GO_VER}.linux-amd64.tar.gz"
  fi
  curl -fsSL "https://go.dev/dl/${GO_TAR}" -o /tmp/${GO_TAR}
  rm -rf "${GO_LOCAL_DIR}" || true
  tar -C "${HOME}/.local" -xzf "/tmp/${GO_TAR}"
  rm "/tmp/${GO_TAR}"
  export PATH="${GO_LOCAL_DIR}/bin:${PATH}"
  log "Installed portable Go: $(${GO_LOCAL_BIN} version)"
}

# Prefer portable Go if we just installed it
maybe_use_portable_go() {
  if [[ -x "${GO_LOCAL_BIN}" ]]; then
    export PATH="${GO_LOCAL_DIR}/bin:${PATH}"
  fi
}

init_git() {
  if [ ! -d .git ]; then
    log "Initializing a fresh git repo"
    git init -q
    git branch -M main || true
    git config user.email "${GIT_AUTHOR_EMAIL:-you@example.com}" || true
    git config user.name "${GIT_AUTHOR_NAME:-Your Name}" || true
  else
    log "Git repo already exists"
  fi
  # Ensure .gitignore ignores the aggregator binary and output dirs
  if ! grep -q '^aggregator$' .gitignore 2>/dev/null; then
    {
      echo "aggregator"
      echo "output/"
      echo "Base64/"
      echo "Splitted-By-Protocol/"
    } >> .gitignore
  fi
}

# --------------- write files ---------------

write_go_files() {
  mkdir -p "${FILES_DIR}"

  # go.mod
  cat > "${FILES_DIR}/go.mod" <<'EOF_GO_MOD'
module local/aggregator

go 1.21
EOF_GO_MOD

  # main.go
  cat > "${FILES_DIR}/main.go" <<'EOF_MAIN_GO'
package main

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// ---------- Types ----------

type NodeMeta struct {
	Proto      string
	Host       string
	Port       int
	TLS        bool
	Path       string
	HostHeader string
	SNI        string
	Raw        string
}

type ProbeResult struct {
	OK bool
}

// ---------- Globals ----------

var userAgent = "Mozilla/5.0 (Aggregator; +https://github.com/) GoV2 Aggregator/1.0"

var sources = []string{
	// yasi-python sources
	"https://raw.githubusercontent.com/yasi-python/PSGd/refs/heads/main/output/base64/mix",
	"https://raw.githubusercontent.com/yasi-python/PSGS/refs/heads/main/subscriptions/xray/base64/mix",
	"https://raw.githubusercontent.com/yasi-python/vip/refs/heads/master/sub/sub_merge_base64.txt",
	// ail-python variants (in case those are the correct ones)
	"https://raw.githubusercontent.com/ail-python/PSGd/refs/heads/main/output/base64/mix",
	"https://raw.githubusercontent.com/ail-python/PSGS/refs/heads/main/subscriptions/xray/base64/mix",
	"https://raw.githubusercontent.com/ail-python/vip/refs/heads/master/sub/sub_merge_base64.txt",
	// popular public sources
	"https://raw.githubusercontent.com/barry-far/V2ray-Config/refs/heads/main/All_Configs_base64_Sub.txt",
	"https://raw.githubusercontent.com/mahdibland/V2RayAggregator/refs/heads/master/sub/sub_merge_base64.txt",
	"https://raw.githubusercontent.com/SoliSpirit/v2ray-configs/refs/heads/main/all_configs.txt",
	"https://raw.githubusercontent.com/Epodonios/v2ray-configs/refs/heads/main/All_Configs_base64_Sub.txt",
	"https://raw.githubusercontent.com/Danialsamadi/v2go/refs/heads/main/All_Configs_Sub.txt",
}

var (
	vmessRe   = regexp.MustCompile(`(?i)^vmess://`)
	genericRe = regexp.MustCompile(`(?i)^(vless|trojan|ss|socks5?|hy2)://`)
	// Extract tokens anywhere in text (greedy until whitespace)
	tokenRe = regexp.MustCompile(`(?i)(vmess|vless|trojan|ss|socks5?|hy2)://[^\s]+`)
)

// ---------- Utils ----------

func logf(s string, a ...any) {
	ts := time.Now().UTC().Format(time.RFC3339)
	fmt.Printf("[%s] %s\n", ts, fmt.Sprintf(s, a...))
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func normalizeB64(s string) string {
	s = strings.TrimSpace(s)
	s = strings.ReplaceAll(s, "\n", "")
	s = strings.ReplaceAll(s, "\r", "")
	s = strings.ReplaceAll(s, "\t", "")
	// Remove URL-safe chars replacement; we'll try multiple decoders anyway
	return s
}

func b64TryAll(s string) ([]byte, error) {
	s = normalizeB64(s)
	// pad for StdEncoding
	if mod := len(s) % 4; mod != 0 {
		s += strings.Repeat("=", 4-mod)
	}
	var data []byte
	var err error
	decoders := []*base64.Encoding{
		base64.StdEncoding,
		base64.URLEncoding,
		base64.RawStdEncoding,
		base64.RawURLEncoding,
	}
	for _, enc := range decoders {
		data, err = enc.DecodeString(s)
		if err == nil {
			return data, nil
		}
	}
	return nil, err
}

func maybeDecodeBigBase64Block(s string) string {
	txt := strings.TrimSpace(s)
	if len(txt) < 48 {
		return s
	}
	candidate := normalizeB64(txt)
	if !regexp.MustCompile(`^[A-Za-z0-9_\-\+/=]+$`).MatchString(candidate) {
		return s
	}
	if dec, err := b64TryAll(candidate); err == nil {
		ds := string(dec)
		if strings.Contains(ds, "vmess://") || strings.Contains(ds, "vless://") || strings.Contains(ds, "trojan://") ||
			strings.Contains(ds, "ss://") || strings.Contains(ds, "socks://") || strings.Contains(ds, "socks5://") {
			return ds
		}
	}
	return s
}

func uniqueStrings(in []string) []string {
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, s := range in {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	return out
}

// ---------- Extraction ----------

func ExtractNodesFromText(text string) []string {
	// Try to decode whole-block base64 first
	txt := maybeDecodeBigBase64Block(text)

	out := make([]string, 0, 512)
	seen := map[string]struct{}{}

	// 1) Regex token scan across full text
	matches := tokenRe.FindAllString(txt, -1)
	for _, m := range matches {
		m = strings.TrimSpace(m)
		if m == "" {
			continue
		}
		// strip trailing chars if any common junk got captured
		m = strings.TrimRight(m, " \t\r\n,;")
		if _, ok := seen[m]; !ok {
			seen[m] = struct{}{}
			out = append(out, m)
		}
	}

	// 2) Line scan fallback
	lines := strings.Split(txt, "\n")
	for _, raw := range lines {
		r := strings.TrimSpace(raw)
		if r == "" {
			continue
		}
		if vmessRe.MatchString(r) || genericRe.MatchString(r) {
			if _, ok := seen[r]; !ok {
				seen[r] = struct{}{}
				out = append(out, r)
			}
			continue
		}
		for _, tok := range []string{"vmess://", "vless://", "trojan://", "ss://", "socks://", "socks5://"} {
			lr := strings.ToLower(r)
			if i := strings.Index(lr, tok); i >= 0 {
				part := strings.TrimSpace(r[i:])
				if _, ok := seen[part]; !ok {
					seen[part] = struct{}{}
					out = append(out, part)
				}
			}
		}
	}
	return out
}

// ---------- Parsing ----------

func parseSSHostPort(raw string) (host string, port int) {
	// Handle both ss://base64(method:password@host:port) and ss://method:password@host:port
	s := strings.TrimSpace(raw)
	if !strings.HasPrefix(strings.ToLower(s), "ss://") {
		return "", 0
	}
	body := s[5:] // after ss://
	// split by '#', '?' as they may be suffix tags
	stop := len(body)
	if idx := strings.IndexAny(body, "#?"); idx >= 0 {
		stop = idx
	}
	core := body[:stop]
	// If it contains '@' then url.Parse can get host:port
	if strings.Contains(core, "@") {
		if u, err := url.Parse(s); err == nil {
			if h := u.Hostname(); h != "" {
				host = h
			}
			if p := u.Port(); p != "" {
				if v, _ := strconv.Atoi(p); v > 0 {
					port = v
				}
			}
		}
		return
	}
	// Otherwise core is base64-encoded "method:password@host:port"
	if dec, err := b64TryAll(core); err == nil {
		val := string(dec)
		// find last '@' then host:port
		at := strings.LastIndex(val, "@")
		if at >= 0 && at < len(val)-1 {
			hostport := val[at+1:]
			if hp, err := url.Parse("ss://" + hostport); err == nil {
				if h := hp.Hostname(); h != "" {
					host = h
				}
				if p := hp.Port(); p != "" {
					if v, _ := strconv.Atoi(p); v > 0 {
						port = v
					}
				}
			} else {
				// fallback regex
				re := regexp.MustCompile(`^(.*@)?([A-Za-z0-9\.\-:]+)$`)
				if m := re.FindStringSubmatch(hostport); len(m) == 3 {
					hp2 := m[2]
					if i := strings.LastIndex(hp2, ":"); i > 0 && i < len(hp2)-1 {
						host = hp2[:i]
						if v, _ := strconv.Atoi(hp2[i+1:]); v > 0 {
							port = v
						}
					}
				}
			}
		}
	}
	return
}

func ParseNode(raw string) NodeMeta {
	n := NodeMeta{Raw: strings.TrimSpace(raw)}
	l := strings.ToLower(n.Raw)

	// vmess
	if strings.HasPrefix(l, "vmess://") {
		n.Proto = "vmess"
		payload := strings.TrimSpace(n.Raw[len("vmess://"):])
		dec, err := b64TryAll(payload)
		if err == nil {
			var j map[string]any
			if json.Unmarshal(dec, &j) == nil {
				if v, ok := j["add"].(string); ok {
					n.Host = v
				}
				if v, ok := j["host"].(string); ok && n.Host == "" {
					n.Host = v
				}
				switch p := j["port"].(type) {
				case string:
					if v, _ := strconv.Atoi(p); v > 0 {
						n.Port = v
					}
				case float64:
					n.Port = int(p)
				}
				// TLS flags
				if v, ok := j["tls"].(string); ok && (strings.EqualFold(v, "tls") || v == "1" || strings.EqualFold(v, "true")) {
					n.TLS = true
				}
				if v, ok := j["security"].(string); ok && strings.EqualFold(v, "tls") {
					n.TLS = true
				}
				// WS path
				if v, ok := j["net"].(string); ok && strings.EqualFold(v, "ws") {
					if pth, ok := j["path"].(string); ok {
						n.Path = pth
					}
				}
				// SNI
				if v, ok := j["sni"].(string); ok && v != "" {
					n.SNI = v
				}
			}
		}
		// Defaults
		if n.Port == 0 {
			if n.TLS {
				n.Port = 443
			} else {
				n.Port = 80
			}
		}
		return n
	}

	// generic URL-like schemes
	if genericRe.MatchString(l) {
		u, err := url.Parse(n.Raw)
		if err == nil {
			n.Proto = strings.ToLower(u.Scheme)
			if u.Hostname() != "" {
				n.Host = u.Hostname()
			}
			if u.Port() != "" {
				if v, _ := strconv.Atoi(u.Port()); v > 0 {
					n.Port = v
				}
			}
			q := u.Query()
			if v := q.Get("security"); strings.Contains(strings.ToLower(v), "tls") {
				n.TLS = true
			}
			if v := q.Get("encryption"); strings.Contains(strings.ToLower(v), "tls") {
				n.TLS = true
			}
			if v := q.Get("sni"); v != "" {
				n.SNI = v
			}
			if v := q.Get("host"); v != "" {
				n.HostHeader = v
			}
			if v := q.Get("path"); v != "" {
				n.Path = v
			}
			// Special handling for ss:// base64
			if n.Proto == "ss" {
				h, p := parseSSHostPort(n.Raw)
				if h != "" {
					n.Host = h
				}
				if p > 0 {
					n.Port = p
				}
			}
		}
		// defaults
		if n.Port == 0 {
			if n.TLS {
				n.Port = 443
			} else {
				n.Port = 80
			}
		}
		// socks alias
		if n.Proto == "socks" {
			n.Proto = "socks5"
		}
		return n
	}

	// last-resort host:port extraction
	hostport := regexp.MustCompile(`([0-9a-zA-Z\.\-]+\.[a-zA-Z]{2,}|[0-9]{1,3}(?:\.[0-9]{1,3}){3}):([0-9]{2,5})`)
	if m := hostport.FindStringSubmatch(n.Raw); len(m) == 3 {
		n.Host = m[1]
		n.Port, _ = strconv.Atoi(m[2])
	}
	if n.Port == 0 {
		n.Port = 80
	}
	return n
}

// ---------- Networking / Probing ----------

func dialTCP(ctx context.Context, host string, port int, timeout time.Duration) (time.Duration, error) {
	start := time.Now()
	d := &net.Dialer{
		Timeout:   timeout,
		KeepAlive: 10 * time.Second,
	}
	c, err := d.DialContext(ctx, "tcp", fmt.Sprintf("%s:%d", host, port))
	if err != nil {
		return 0, err
	}
	defer c.Close()
	return time.Since(start), nil
}

func tlsHandshake(ctx context.Context, host string, port int, sni string, timeout time.Duration) (time.Duration, error) {
	start := time.Now()
	d := &net.Dialer{
		Timeout:   timeout,
		KeepAlive: 10 * time.Second,
	}
	serverName := host
	if sni != "" {
		serverName = sni
	}
	cfg := &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         serverName,
		MinVersion:         tls.VersionTLS12,
	}
	conn, err := tls.DialWithDialer(d, "tcp", fmt.Sprintf("%s:%d", host, port), cfg)
	if err != nil {
		return 0, err
	}
	defer conn.Close()
	return time.Since(start), nil
}

func MultiLevelProbe(ctx context.Context, nm NodeMeta, timeout time.Duration) ProbeResult {
	res := ProbeResult{OK: false}
	// Candidate ports if missing were set in ParseNode
	candidates := []int{nm.Port}
	// If invalid port got set to <=0, try sane defaults
	if nm.Port <= 0 {
		if nm.TLS {
			candidates = []int{443, 8443}
		} else {
			candidates = []int{80, 8080}
		}
	}

	for _, p := range candidates {
		_, err := dialTCP(ctx, nm.Host, p, timeout)
		if err != nil {
			continue
		}
		// If TLS node, require successful handshake too
		if nm.TLS {
			if _, err := tlsHandshake(ctx, nm.Host, p, nm.SNI, timeout); err != nil {
				continue
			}
		}
		res.OK = true
		break
	}
	return res
}

// ---------- Fetch ----------

func httpClient() *http.Client {
	tr := &http.Transport{
		TLSHandshakeTimeout:   10 * time.Second,
		IdleConnTimeout:       30 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		DisableCompression:    false,
		Proxy:                 http.ProxyFromEnvironment,
	}
	return &http.Client{
		Timeout:   30 * time.Second,
		Transport: tr,
	}
}

func fetchURL(u string) (string, error) {
	req, err := http.NewRequest("GET", u, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", userAgent)

	resp, err := httpClient().Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return "", fmt.Errorf("status %d", resp.StatusCode)
	}
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// ---------- Output Helpers ----------

func writeFile(path string, data []byte) error {
	if err := os.MkdirAll(filepathDir(path), 0o755); err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o644)
}

func filepathDir(p string) string {
	if i := strings.LastIndex(p, "/"); i >= 0 {
		return p[:i]
	}
	return "."
}

// ---------- Main ----------

func main() {
	start := time.Now()
	logf("Starting aggregator and probe...")

	// Concurrency limits
	maxFetch := min(12, 4*runtime.NumCPU())
	maxProbe := min(256, 64*runtime.NumCPU())
	probeTimeout := 5 * time.Second

	var (
		allNodesMu sync.Mutex
		allNodes   []string
	)

	// Fetch sources
	logf("Fetching %d sources with concurrency=%d", len(sources), maxFetch)
	fetchSem := make(chan struct{}, maxFetch)
	var wgFetch sync.WaitGroup
	for _, src := range sources {
		wgFetch.Add(1)
		fetchSem <- struct{}{}
		go func(u string) {
			defer wgFetch.Done()
			defer func() { <-fetchSem }()
			txt, err := fetchURL(u)
			if err != nil {
				logf("Fetch error %s: %v", u, err)
				return
			}
			nodes := ExtractNodesFromText(txt)
			if len(nodes) == 0 {
				// attempt base64 decode of full content then re-extract
				decoded := maybeDecodeBigBase64Block(txt)
				if decoded != txt {
					nodes = ExtractNodesFromText(decoded)
				}
			}
			if len(nodes) > 0 {
				allNodesMu.Lock()
				allNodes = append(allNodes, nodes...)
				allNodesMu.Unlock()
				logf("Source OK: %s -> %d nodes", u, len(nodes))
			} else {
				logf("Source yielded zero nodes: %s", u)
			}
		}(src)
	}
	wgFetch.Wait()

	if len(allNodes) == 0 {
		logf("No nodes found from sources. Still writing empty outputs for workflow stability.")
		writeOutputs([]string{})
		summary(0, 0, time.Since(start))
		return
	}

	// Unique
	unique := uniqueStrings(allNodes)
	logf("Collected %d nodes (%d unique)", len(allNodes), len(unique))

	// Probe with worker pool
	type item struct{ raw string }
	inCh := make(chan item, len(unique))
	for _, u := range unique {
		inCh <- item{raw: u}
	}
	close(inCh)

	var healthyMu sync.Mutex
	healthy := make([]string, 0, len(unique)/2)
	var checked int32

	var wgProbe sync.WaitGroup
	for i := 0; i < maxProbe; i++ {
		wgProbe.Add(1)
		go func() {
			defer wgProbe.Done()
			for it := range inCh {
				atomic.AddInt32(&checked, 1)
				nm := ParseNode(it.raw)
				// only attempt probe if host looks sane
				if nm.Host == "" || nm.Port <= 0 {
					continue
				}
				ctx, cancel := context.WithTimeout(context.Background(), probeTimeout)
				res := MultiLevelProbe(ctx, nm, probeTimeout)
				cancel()
				if res.OK {
					healthyMu.Lock()
					healthy = append(healthy, it.raw)
					healthyMu.Unlock()
				}
			}
		}()
	}
	wgProbe.Wait()

	// Stable order output
	sort.Strings(healthy)
	writeOutputs(healthy)
	summary(len(unique), len(healthy), time.Since(start))
}

func writeOutputs(healthy []string) {
	joined := strings.Join(healthy, "\n")
	if joined != "" && !strings.HasSuffix(joined, "\n") {
		joined += "\n"
	}

	// Root files (for GitHub Actions steps)
	_ = writeFile("All_Configs_Sub.txt", []byte(joined))
	b64 := base64.StdEncoding.EncodeToString([]byte(joined))
	_ = writeFile("All_Configs_base64_Sub.txt", []byte(b64))

	// Output dir (extra)
	_ = writeFile("output/merged_nodes.txt", []byte(joined))
	_ = writeFile("output/merged_sub_base64.txt", []byte(b64))

	// Split by protocol
	byProto := map[string][]string{
		"vmess":  {},
		"vless":  {},
		"trojan": {},
		"ss":     {},
		"socks5": {},
	}
	for _, raw := range healthy {
		p := strings.ToLower(strings.SplitN(raw, "://", 2)[0])
		if p == "socks" {
			p = "socks5"
		}
		if _, ok := byProto[p]; ok {
			byProto[p] = append(byProto[p], raw)
		}
	}
	for proto, list := range byProto {
		content := strings.Join(list, "\n")
		if content != "" && !strings.HasSuffix(content, "\n") {
			content += "\n"
		}
		_ = writeFile(fmt.Sprintf("Splitted-By-Protocol/%s.txt", proto), []byte(content))
		_ = writeFile(fmt.Sprintf("Base64/%s_base64.txt", proto), []byte(base64.StdEncoding.EncodeToString([]byte(content))))
	}
}

func summary(uniqueCount, healthyCount int, dur time.Duration) {
	logf("Processed %d unique configs, %d healthy", uniqueCount, healthyCount)
	logf("Outputs: All_Configs_Sub.txt, All_Configs_base64_Sub.txt, Splitted-By-Protocol/, Base64/, output/")
	logf("Finished in %s", dur.Round(time.Millisecond))
}

// ----- optional: Wilson lower bound kept here only for reference (not used) -----
func wilsonLowerBound(success, total int, z float64) float64 {
	if total == 0 {
		return 0
	}
	n := float64(total)
	p := float64(success) / n
	z2 := z * z
	den := 1 + z2/n
	center := p + z2/(2*n)
	rad := z * math.Sqrt((p*(1-p)+z2/(4*n))/n)
	return (center - rad) / den
}
EOF_MAIN_GO
}

write_workflow() {
  mkdir -p "${WF_DIR}"
  cat > "${WF_DIR}/Update-V2Ray-Configs.yml" <<'EOF_WORKFLOW'
name: Update V2Ray Configs

permissions:
  contents: write
  checks: read

on:
  push:
    branches:
      - main
  schedule:
    - cron: '0 */6 * * *'
  workflow_dispatch:
    inputs:
      force_update:
        description: 'Force update regardless of changes'
        required: false
        default: 'false'

jobs:
  update-configs:
    runs-on: ubuntu-latest
    timeout-minutes: 45
    env:
      GO_VERSION: '1.21'
      OUTPUT_DIR: './output'
      PROTOCOL_DIR: './Splitted-By-Protocol'
      BASE64_DIR: './Base64'

    steps:
      - name: Checkout code
        uses: actions/checkout@v4
        with:
          fetch-depth: 0

      - name: Set up Go
        uses: actions/setup-go@v5
        with:
          go-version: ${{ env.GO_VERSION }}
          cache: true
          cache-dependency-path: 'Files/go.sum'

      - name: Build and run Go aggregator
        id: build-and-run
        run: |
          set -euo pipefail
          echo "Building Go application at $(date -u '+%Y-%m-%d %H:%M:%S UTC')..."
          cd Files || { echo "::error::'Files' directory not found"; exit 1; }
          go mod tidy
          go build -ldflags="-s -w" -o ../aggregator *.go || { echo "::error::Build failed"; exit 1; }
          cd ..
          echo "Starting config aggregation and sorting..."
          ./aggregator || { echo "::error::Aggregator execution failed"; exit 1; }
          echo "Config processing completed successfully!"
          echo "OUTPUT_COUNT=$(ls -1 ${OUTPUT_DIR}/*.txt 2>/dev/null | wc -l)" >> $GITHUB_OUTPUT

      - name: Verify output files
        run: |
          set -euo pipefail
          echo "Verifying generated files at $(date -u '+%Y-%m-%d %H:%M:%S UTC')..."
          echo "Files in root directory:"
          ls -la *.txt 2>/dev/null || echo "No .txt files found in root"
          echo
          echo "Protocol directory contents:"
          ls -la ${PROTOCOL_DIR}/ 2>/dev/null || echo "No protocol directory found"
          echo
          echo "Sub files:"
          ls -la Sub*.txt 2>/dev/null || echo "No Sub files found"
          echo
          echo "Base64 directory contents:"
          ls -la ${BASE64_DIR}/ 2>/dev/null || echo "No Base64 directory found"
          if [ -f "All_Configs_Sub.txt" ]; then
            TOTAL_CONFIGS=$(wc -l < All_Configs_Sub.txt)
            FILE_SIZE=$(du -h All_Configs_Sub.txt | cut -f1)
            echo
            echo "Main config file: $TOTAL_CONFIGS configurations ($FILE_SIZE)"
          elif ls All_Configs_Sub_part_* >/dev/null 2>&1; then
            TOTAL_CONFIGS=$(cat All_Configs_Sub_part_* | wc -l)
            FILE_SIZE=$(du -ch All_Configs_Sub_part_* | grep total | cut -f1)
            echo
            echo "Main config file (split): $TOTAL_CONFIGS configurations ($FILE_SIZE total)"
          else
            echo
            echo "Main config file not found - checking if it was split..."
          fi
          if [ -d "${PROTOCOL_DIR}" ]; then
            echo
            echo "Protocol file statistics:"
            for file in ${PROTOCOL_DIR}/*.txt; do
              if [ -f "$file" ]; then
                count=$(wc -l < "$file")
                size=$(du -h "$file" | cut -f1)
                basename=$(basename "$file")
                echo "  $basename: $count configs ($size)"
              fi
            done
          fi

      - name: Handle large files and prepare for commit
        run: |
          set -euo pipefail
          echo "Checking file sizes and handling large files at $(date -u '+%Y-%m-%d %H:%M:%S UTC')..."
          handle_large_file() {
            local file="$1"
            local prefix="$2"
            local max_size_mb=90
            if [ -f "$file" ]; then
              if stat --version >/dev/null 2>&1; then
                size=$(stat -c%s "$file")
              else
                size=$(stat -f%z "$file")
              fi
              size_mb=$((size / 1024 / 1024))
              echo "File $file size: ${size_mb}MB"
              if [ $size_mb -gt $max_size_mb ]; then
                echo "Splitting large file: $file (size exceeds ${max_size_mb}MB)"
                mkdir -p split_temp
                split -b ${max_size_mb}M "$file" "split_temp/${prefix}_part_"
                rm "$file"
                mv split_temp/${prefix}_part_* .
                rmdir split_temp
                echo "File split into parts with prefix: ${prefix}_part_"
              fi
            fi
          }
          handle_large_file "All_Configs_Sub.txt" "All_Configs_Sub"
          handle_large_file "All_Configs_base64_Sub.txt" "All_Configs_base64_Sub"
          if [ -d "${PROTOCOL_DIR}" ]; then
            for protocol_file in ${PROTOCOL_DIR}/*.txt; do
              if [ -f "$protocol_file" ]; then
                filename=$(basename "$protocol_file" .txt)
                handle_large_file "$protocol_file" "${PROTOCOL_DIR}/${filename}"
              fi
            done
          fi
          for file in *_part_*; do
            if [ -f "$file" ]; then
              if stat --version >/dev/null 2>&1; then
                size=$(stat -c%s "$file")
              else
                size=$(stat -f%z "$file")
              fi
              if [ "$size" -gt $((50 * 1024 * 1024)) ]; then
                echo "Compressing $file..."
                gzip -f "$file"
              fi
            fi
          done

      - name: Create status summary
        run: |
          set -euo pipefail
          echo "# V2Ray Config Update Summary" > UPDATE_SUMMARY.md
          echo "Generated on: $(date -u '+%Y-%m-%d %H:%M:%S UTC')" >> UPDATE_SUMMARY.md
          echo "" >> UPDATE_SUMMARY.md
          echo "## Configuration Statistics" >> UPDATE_SUMMARY.md
          total=0
          if [ -f "All_Configs_Sub.txt" ]; then
            total=$(wc -l < "All_Configs_Sub.txt")
          elif ls All_Configs_Sub_part_* >/dev/null 2>&1; then
            total=$(cat All_Configs_Sub_part_* | wc -l)
          fi
          echo "- Total configurations: $total" >> UPDATE_SUMMARY.md
          if [ -d "${PROTOCOL_DIR}" ]; then
            echo "- Protocol breakdown:" >> UPDATE_SUMMARY.md
            for file in ${PROTOCOL_DIR}/*.txt; do
              if [ -f "$file" ]; then
                protocol=$(basename "$file" .txt)
                count=$(wc -l < "$file")
                echo "  - $protocol: $count configs" >> UPDATE_SUMMARY.md
              fi
            done
          fi
          echo "" >> UPDATE_SUMMARY.md
          echo "## Performance" >> UPDATE_SUMMARY.md
          echo "- Probing timeout per node: 5s" >> UPDATE_SUMMARY.md
          echo "- Concurrency tuned by CPU count" >> UPDATE_SUMMARY.md
          echo "" >> UPDATE_SUMMARY.md
          echo "## System Info" >> UPDATE_SUMMARY.md
          echo "- Runner: ${{ runner.os }} (${{ runner.arch }})" >> UPDATE_SUMMARY.md
          echo "- Go Version: ${{ env.GO_VERSION }}" >> UPDATE_SUMMARY.md

      - name: Commit and push changes
        uses: EndBug/add-and-commit@v9
        with:
          author_name: "GitHub Actions Bot"
          author_email: "github-actions[bot]@users.noreply.github.com"
          message: "🚀 Fresh V2Ray Config Update [${{ github.run_id }}]"
          add: "UPDATE_SUMMARY.md *.txt ${PROTOCOL_DIR}/* ${BASE64_DIR}/*"
          default_author: github_actor
          push: true
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}

      - name: Notify on failure
        if: failure()
        run: |
          echo "::error::Workflow failed at $(date -u '+%Y-%m-%d %H:%M:%S UTC'). Check logs for details."
          exit 1
EOF_WORKFLOW
}

# --------------- build & run ---------------

build_and_run() {
  log "Setting Go proxy for reliability"
  go env -w GOPROXY=https://goproxy.io,direct >/dev/null 2>&1 || true

  log "Tidying Go module"
  (cd "${FILES_DIR}" && go mod tidy)

  log "Building aggregator"
  (cd "${FILES_DIR}" && go build -ldflags="-s -w" -o "${ROOT_DIR}/aggregator" *.go)

  log "Running aggregator (this will fetch sources, probe, and write outputs)"
  "${ROOT_DIR}/aggregator" || true

  log "Listing outputs"
  ls -la "${ROOT_DIR}"/*.txt 2>/dev/null || true
  ls -la "${PROTO_DIR}" 2>/dev/null || true
  ls -la "${BASE64_DIR}" 2>/dev/null || true
  ls -la "${OUTPUT_DIR}" 2>/dev/null || true
}

git_commit_hint() {
  init_git
  git add -A || true
  git commit -m "chore: bootstrap aggregator, workflow, and first outputs" || true
  log "Bootstrap complete. If this is a new repo, push and enable Actions:"
  echo "  git remote add origin <your-repo-url>"
  echo "  git push -u origin main"
  echo "Then check Actions tab for scheduled/triggered runs."
}

# --------------- main ---------------

main() {
  log "Bootstrap starting"
  ensure_go
  maybe_use_portable_go
  write_go_files
  write_workflow
  build_and_run
  git_commit_hint
  log "All done!"
}

main