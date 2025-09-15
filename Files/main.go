package main

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
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

// ---------- Sources ----------

var defaultSources = []string{
	"https://raw.githubusercontent.com/yasi-python/PSGd/refs/heads/main/output/base64/mix",
	"https://raw.githubusercontent.com/yasi-python/PSGS/refs/heads/main/subscriptions/xray/base64/mix",
	"https://raw.githubusercontent.com/yasi-python/vip/refs/heads/master/sub/sub_merge_base64.txt",
	"https://raw.githubusercontent.com/ail-python/PSGd/refs/heads/main/output/base64/mix",
	"https://raw.githubusercontent.com/ail-python/PSGS/refs/heads/main/subscriptions/xray/base64/mix",
	"https://raw.githubusercontent.com/ail-python/vip/refs/heads/master/sub/sub_merge_base64.txt",
	"https://raw.githubusercontent.com/barry-far/V2ray-Config/refs/heads/main/All_Configs_base64_Sub.txt",
	"https://raw.githubusercontent.com/mahdibland/V2RayAggregator/refs/heads/master/sub/sub_merge_base64.txt",
	"https://raw.githubusercontent.com/SoliSpirit/v2ray-configs/refs/heads/main/all_configs.txt",
	"https://raw.githubusercontent.com/Epodonios/v2ray-configs/refs/heads/main/All_Configs_base64_Sub.txt",
	"https://raw.githubusercontent.com/Danialsamadi/v2go/refs/heads/main/All_Configs_Sub.txt",
}

// ---------- Regex ----------

var (
	vmessRe   = regexp.MustCompile(`(?i)^vmess://`)
	genericRe = regexp.MustCompile(`(?i)^(vless|trojan|ss|socks5?|hy2)://`)
	tokenRe   = regexp.MustCompile(`(?i)(vmess|vless|trojan|ss|socks5?|hy2)://[^\s]+`)
)

// ---------- Utils ----------

func logf(s string, a ...any) {
	ts := time.Now().UTC().Format(time.RFC3339)
	fmt.Printf("[%s] %s\n", ts, fmt.Sprintf(s, a...))
}

func getEnvString(name, def string) string {
	if v := strings.TrimSpace(os.Getenv(name)); v != "" {
		return v
	}
	return def
}

func getEnvBool(name string, def bool) bool {
	v := strings.TrimSpace(strings.ToLower(os.Getenv(name)))
	if v == "" {
		return def
	}
	switch v {
	case "1", "true", "yes", "on":
		return true
	case "0", "false", "no", "off":
		return false
	default:
		return def
	}
}

func getEnvInt(name string, def int) int {
	v := strings.TrimSpace(os.Getenv(name))
	if v == "" {
		return def
	}
	if n, err := strconv.Atoi(v); err == nil {
		return n
	}
	return def
}

func getEnvDuration(name string, def time.Duration) time.Duration {
	v := strings.TrimSpace(os.Getenv(name))
	if v == "" {
		return def
	}
	if d, err := time.ParseDuration(v); err == nil {
		return d
	}
	if n, err := strconv.Atoi(v); err == nil {
		return time.Duration(n) * time.Second
	}
	return def
}

func normalizeB64(s string) string {
	s = strings.TrimSpace(s)
	s = strings.ReplaceAll(s, "\n", "")
	s = strings.ReplaceAll(s, "\r", "")
	s = strings.ReplaceAll(s, "\t", "")
	return s
}

func b64TryAll(s string) ([]byte, error) {
	s = normalizeB64(s)
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
	txt := maybeDecodeBigBase64Block(text)

	out := make([]string, 0, 1024)
	seen := map[string]struct{}{}

	// Token scan
	matches := tokenRe.FindAllString(txt, -1)
	for _, m := range matches {
		m = strings.TrimSpace(strings.TrimRight(m, " \t\r\n,;"))
		if m == "" {
			continue
		}
		if _, ok := seen[m]; !ok {
			seen[m] = struct{}{}
			out = append(out, m)
		}
	}

	// Line scan fallback
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
	s := strings.TrimSpace(raw)
	if !strings.HasPrefix(strings.ToLower(s), "ss://") {
		return "", 0
	}
	body := s[5:]
	stop := len(body)
	if idx := strings.IndexAny(body, "#?"); idx >= 0 {
		stop = idx
	}
	core := body[:stop]
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
	if dec, err := b64TryAll(core); err == nil {
		val := string(dec)
		at := strings.LastIndex(val, "@")
		if at >= 0 && at < len(val)-1 {
			hostport := val[at+1:]
			if i := strings.LastIndex(hostport, ":"); i > 0 && i < len(hostport)-1 {
				host = hostport[:i]
				if v, _ := strconv.Atoi(hostport[i+1:]); v > 0 {
					port = v
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
				if v, ok := j["tls"].(string); ok && (strings.EqualFold(v, "tls") || v == "1" || strings.EqualFold(v, "true")) {
					n.TLS = true
				}
				if v, ok := j["security"].(string); ok && (strings.EqualFold(v, "tls") || strings.EqualFold(v, "reality") || strings.Contains(strings.ToLower(v), "xtls")) {
					n.TLS = true
				}
				if v, ok := j["net"].(string); ok && strings.EqualFold(v, "ws") {
					if pth, ok := j["path"].(string); ok {
						n.Path = pth
					}
				}
				if v, ok := j["sni"].(string); ok && v != "" {
					n.SNI = v
				}
			}
		}
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
			if v := q.Get("security"); strings.Contains(strings.ToLower(v), "tls") || strings.Contains(strings.ToLower(v), "reality") || strings.Contains(strings.ToLower(v), "xtls") {
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
		if n.Port == 0 {
			if n.TLS {
				n.Port = 443
			} else {
				n.Port = 80
			}
		}
		if n.Proto == "socks" {
			n.Proto = "socks5"
		}
		return n
	}

	// last-resort host:port
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
	c, err := d.DialContext(ctx, "tcp", net.JoinHostPort(host, strconv.Itoa(port)))
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
	conn, err := tls.DialWithDialer(d, "tcp", net.JoinHostPort(host, strconv.Itoa(port)), cfg)
	if err != nil {
		return 0, err
	}
	defer conn.Close()
	return time.Since(start), nil
}

func MultiLevelProbe(ctx context.Context, nm NodeMeta, quickTimeout, fullTimeout time.Duration, preferTLS, requireTLS bool) ProbeResult {
	res := ProbeResult{OK: false}

	// candidate ports (unique)
	ports := []int{}
	addPort := func(p int) {
		for _, x := range ports {
			if x == p {
				return
			}
		}
		if p > 0 {
			ports = append(ports, p)
		}
	}
	addPort(nm.Port)
	if nm.TLS {
		addPort(443)
		addPort(8443)
	} else {
		addPort(80)
		addPort(8080)
	}

	for _, p := range ports {
		// fast path
		if _, err := dialTCP(ctx, nm.Host, p, quickTimeout); err == nil {
			if nm.TLS && preferTLS {
				if _, err := tlsHandshake(ctx, nm.Host, p, nm.SNI, fullTimeout); err != nil {
					if requireTLS {
						continue
					}
					// TLS failed but allowed: TCP was OK -> accept
				}
			}
			res.OK = true
			break
		}
		// slow path
		if _, err := dialTCP(ctx, nm.Host, p, fullTimeout); err == nil {
			if nm.TLS && preferTLS {
				if _, err := tlsHandshake(ctx, nm.Host, p, nm.SNI, fullTimeout); err != nil {
					if requireTLS {
						continue
					}
				}
			}
			res.OK = true
			break
		}
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
	req.Header.Set("User-Agent", "Mozilla/5.0 (Aggregator) GoV2/1.0")
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

func writeOutputs(healthy []string) {
	joined := strings.Join(healthy, "\n")
	if joined != "" && !strings.HasSuffix(joined, "\n") {
		joined += "\n"
	}

	// Root files
	_ = writeFile("All_Configs_Sub.txt", []byte(joined))
	b64 := base64.StdEncoding.EncodeToString([]byte(joined))
	_ = writeFile("All_Configs_base64_Sub.txt", []byte(b64))

	// output/
	_ = writeFile("output/merged_nodes.txt", []byte(joined))
	_ = writeFile("output/merged_sub_base64.txt", []byte(b64))

	// Split by protocol and prepare Base64 per-proto
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

func loadSources() []string {
	custom := strings.TrimSpace(os.Getenv("AGG_SOURCES_FILE"))
	if custom == "" {
		return defaultSources
	}
	data, err := os.ReadFile(custom)
	if err != nil {
		logf("Failed to read AGG_SOURCES_FILE=%s: %v, fallback to defaults", custom, err)
		return defaultSources
	}
	out := []string{}
	for _, ln := range strings.Split(string(data), "\n") {
		s := strings.TrimSpace(ln)
		if s == "" || strings.HasPrefix(s, "#") {
			continue
		}
		out = append(out, s)
	}
	if len(out) == 0 {
		return defaultSources
	}
	return out
}

// ---------- Probe runner ----------

func runProbe(unique []string, quickTimeout, fullTimeout time.Duration, maxProbe int, preferTLS, requireTLS bool, progressEvery int) []string {
	total := len(unique)
	if total == 0 {
		return nil
	}
	workers := maxProbe
	if workers < 1 {
		workers = 1
	}
	if workers > total {
		workers = total
	}

	type item struct{ raw string }
	inCh := make(chan item, total)
	for _, u := range unique {
		inCh <- item{raw: u}
	}
	close(inCh)

	var healthyMu sync.Mutex
	healthy := make([]string, 0, total/3)
	var checked int32
	var healthyCount int32

	var wgProbe sync.WaitGroup
	for i := 0; i < workers; i++ {
		wgProbe.Add(1)
		go func() {
			defer wgProbe.Done()
			for it := range inCh {
				idx := atomic.AddInt32(&checked, 1)
				nm := ParseNode(it.raw)
				if nm.Host == "" || nm.Port <= 0 {
					continue
				}
				ctx, cancel := context.WithTimeout(context.Background(), fullTimeout+quickTimeout)
				res := MultiLevelProbe(ctx, nm, quickTimeout, fullTimeout, preferTLS, requireTLS)
				cancel()
				if res.OK {
					healthyMu.Lock()
					healthy = append(healthy, it.raw)
					healthyMu.Unlock()
					atomic.AddInt32(&healthyCount, 1)
				}
				if progressEvery > 0 && idx%int32(progressEvery) == 0 {
					logf("Probed %d/%d, healthy=%d", idx, total, atomic.LoadInt32(&healthyCount))
				}
			}
		}()
	}
	wgProbe.Wait()
	return healthy
}

// ---------- Main ----------

func main() {
	start := time.Now()
	logf("Starting aggregator + probe...")

	// Env config
	maxFetch := getEnvInt("AGG_MAX_FETCH", 12)
	maxProbe := getEnvInt("AGG_MAX_PROBE", minInt(256, 64*runtime.NumCPU()))
	quickTimeout := getEnvDuration("AGG_QUICK_TIMEOUT", 1200*time.Millisecond)
	fullTimeout := getEnvDuration("AGG_PROBE_TIMEOUT", 4*time.Second)
	noProbe := getEnvBool("AGG_NO_PROBE", false)
	autoFallback := getEnvBool("AGG_AUTO_FALLBACK", true)
	minHealthy := getEnvInt("AGG_MIN_HEALTHY_THRESHOLD", 50)
	progressEvery := getEnvInt("AGG_PROGRESS_EVERY", 800)

	// Strategy
	strategy := strings.ToLower(getEnvString("AGG_PROBE_STRATEGY", "auto")) // auto | tcp | tcp+tls | tls | tls-only
	preferTLS := true
	requireTLS := false
	switch strategy {
	case "tcp":
		preferTLS, requireTLS = false, false
	case "tcp+tls", "auto":
		preferTLS, requireTLS = true, false
	case "tls", "tls-only":
		preferTLS, requireTLS = true, true
	}

	// Fetch sources
	sources := loadSources()
	logf("Fetching %d sources with concurrency=%d", len(sources), maxFetch)
	var allNodesMu sync.Mutex
	allNodes := []string{}
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
		logf("No nodes found. Writing empty outputs for stability.")
		writeOutputs([]string{})
		logf("Finished in %s", time.Since(start).Round(time.Millisecond))
		return
	}

	unique := uniqueStrings(allNodes)
	logf("Collected %d nodes (%d unique)", len(allNodes), len(unique))

	var healthy []string

	if noProbe {
		logf("AGG_NO_PROBE=1 -> skipping probes, writing deduped list")
		healthy = unique
	} else {
		healthy = runProbe(unique, quickTimeout, fullTimeout, maxProbe, preferTLS, requireTLS, progressEvery)
		logf("Initial probe (strategy=%s) healthy=%d", strategy, len(healthy))

		if autoFallback && len(healthy) < minHealthy {
			// Fallback 1: TCP+TLS (optional TLS)
			logf("Auto-fallback: too few healthy (<%d). Retrying with strategy=tcp+tls (optional TLS)", minHealthy)
			healthy = runProbe(unique, quickTimeout, fullTimeout, maxProbe, true, false, progressEvery)
			logf("Fallback tcp+tls healthy=%d", len(healthy))
		}
		if autoFallback && len(healthy) < minHealthy {
			// Fallback 2: TCP-only
			logf("Auto-fallback: still few. Retrying with strategy=tcp (TCP-only)")
			healthy = runProbe(unique, quickTimeout, fullTimeout, maxProbe, false, false, progressEvery)
			logf("Fallback tcp-only healthy=%d", len(healthy))
		}
		if autoFallback && len(healthy) < minHealthy {
			// Fallback 3: No probe
			logf("Auto-fallback: still few. Using deduped list without probing.")
			healthy = unique
		}
	}

	sort.Strings(healthy)
	writeOutputs(healthy)

	logf("Processed %d unique, %d output", len(unique), len(healthy))
	logf("Outputs ready: All_Configs_Sub.txt, All_Configs_base64_Sub.txt, Splitted-By-Protocol/, Base64/, output/")
	logf("Finished in %s", time.Since(start).Round(time.Millisecond))
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}
