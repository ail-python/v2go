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
