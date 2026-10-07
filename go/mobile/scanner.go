// Package mobile exposes a small, versioned JSON bridge to the same scan engine
// used by the CLI and desktop UI. No probing logic is implemented on Android.
package mobile

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"reachability-scanner/engine"
)

type request struct {
	Mode      string             `json:"mode"`
	Provider  string             `json:"provider"`
	Targets   string             `json:"targets"`
	InputPath string             `json:"inputPath"`
	Options   *engine.ScanConfig `json:"options"`
}
type snapshot struct {
	Run     string  `json:"run"`
	Mode    string  `json:"mode"`
	State   string  `json:"state"`
	Busy    bool    `json:"busy"`
	Done    int     `json:"done"`
	Total   int     `json:"total"`
	Open    int     `json:"open"`
	Dead    int     `json:"dead"`
	Rows    int     `json:"rows"`
	Error   string  `json:"error"`
	Elapsed float64 `json:"elapsed"`
	// Counts matches the desktop result categories: all, ok, dead, poisoned, hijacked, tunnel.
	Counts map[string]int `json:"counts"`
}

// category mirrors the desktop GUI: poisoned, then failed, else reachable.
func category(r *engine.ScanResult) string {
	switch {
	case r.IsPoisoned:
		return "poisoned"
	case r.Error != "":
		return "dead"
	}
	return "ok"
}
func hijacked(r *engine.ScanResult) bool {
	return r.DnsProtocol != "" && r.ResolvedIP != "" && engine.IsHijackedIP(r.ResolvedIP)
}
func countResult(counts map[string]int, r *engine.ScanResult) {
	counts["all"]++
	counts[category(r)]++
	if hijacked(r) {
		counts["hijacked"]++
	}
	if r.TunnelReady {
		counts["tunnel"]++
	}
}

// Scanner owns a single scan and an independently cancellable speed test.
type Scanner struct {
	mu            sync.Mutex
	root          string
	current       snapshot
	engine        *engine.Engine
	config        *engine.ScanConfig
	started       time.Time
	ready         chan struct{}
	stopRequested bool
	index         []int64
	rows          *os.File
	csvFile       *os.File
	csv           *csv.Writer
	speedCancel   context.CancelFunc
}

func NewScanner(root string) (*Scanner, error) {
	if !filepath.IsAbs(root) {
		return nil, fmt.Errorf("scanner storage must be an absolute path")
	}
	if err := os.MkdirAll(root, 0700); err != nil {
		return nil, err
	}
	return &Scanner{root: root, current: snapshot{State: "idle"}}, nil
}
func (s *Scanner) Catalog() string {
	return encode(map[string]any{"version": 1, "modes": engine.ScanModes(), "providers": engine.EdgeProviders(), "domains": engine.DefaultProbeDomains()})
}
func encode(v any) string { b, _ := json.Marshal(v); return string(b) }

func buildConfig(r request) (*engine.ScanConfig, error) {
	cfg := r.Options
	if cfg == nil {
		cfg = engine.DefaultConfig()
	}
	if err := cfg.ValidateAntiDPI(); err != nil {
		return nil, err
	}
	if cfg.MaxConcurrent < 1 || cfg.MaxConcurrent > 5000 {
		return nil, fmt.Errorf("concurrency must be 1–5000")
	}
	if cfg.MinConcurrent < 1 || cfg.MinConcurrent > cfg.MaxConcurrent {
		return nil, fmt.Errorf("automatic minimum must be 1–maximum concurrency")
	}
	if cfg.TimeoutSecs < 1 || cfg.TimeoutSecs > 120 || cfg.RetryCount < 0 || cfg.RetryCount > 10 {
		return nil, fmt.Errorf("use 1–120 seconds and 0–10 retries")
	}
	for _, port := range cfg.CustomPorts {
		if port < 1 || port > 65535 {
			return nil, fmt.Errorf("ports must be 1–65535")
		}
	}
	cfg.ScanAllPorts, cfg.SNIScan, cfg.DnsDiscoveryMode, cfg.DnsUdpTcpOnly, cfg.DnsTxtMode = false, false, false, false, false
	cfg.ProxyMode = ""
	switch r.Mode {
	case "http", "http-all", "custom":
		provider, ok := engine.FindEdgeProvider(r.Provider)
		if !ok {
			return nil, fmt.Errorf("select an edge provider")
		}
		allowed := false
		for _, mode := range provider.Modes {
			if mode == r.Mode {
				allowed = true
			}
		}
		if !allowed {
			return nil, fmt.Errorf("this provider does not support the selected port mode")
		}
		cfg.EdgeProvider = provider.ID
		cfg.RequiredProbeDomains = append([]string(nil), provider.PlatformDomains...)
		if len(cfg.ProbeDomains) == 0 {
			cfg.ProbeDomains = provider.ProbeDomains
		}
		if provider.ID == "custom" && len(cfg.RequiredProbeDomains) == 0 {
			cfg.RequiredProbeDomains = cfg.ProbeDomains
		}
		if cfg.TargetType != "ip" && cfg.TargetType != "domain" {
			return nil, fmt.Errorf("choose IPs or edge domains")
		}
		cfg.ScanAllPorts = r.Mode == "http-all"
		if r.Mode == "custom" && len(cfg.CustomPorts) == 0 {
			return nil, fmt.Errorf("enter custom ports")
		}
		if r.Mode != "custom" {
			cfg.CustomPorts = nil
		}
	case "sni":
		cfg.SNIScan = true
		if err := engine.ValidateSNI(cfg.SpoofedSNI); err != nil {
			return nil, err
		}
		cfg.ProbeDomains = nil
		cfg.TargetType = ""
	case "http-proxy", "socks-proxy":
		cfg.ProxyMode = "http"
		if r.Mode == "socks-proxy" {
			cfg.ProxyMode = "socks5"
		}
		if _, err := engine.ParseProbeURL(cfg.ProxyTestURL); err != nil {
			return nil, err
		}
		cfg.ProbeDomains = nil
		cfg.TargetType = ""
	case "dns", "dns-udptcp", "txt":
		if cfg.DnsMaxPingMs < 1 || cfg.DnsMaxPingMs > 120000 || cfg.DnsRateLimitPerSecond < 0 || cfg.DnsRateLimitPerResolverPerSecond < 0 || cfg.DnsRateLimitBurst < 1 || cfg.DnsTimingJitter < 0 || cfg.DnsTimingJitter > 1 {
			return nil, fmt.Errorf("DNS: use 1–120000 ms ping, nonnegative rates, burst ≥1 and jitter 0–1")
		}
		cfg.DnsDiscoveryMode = true
		cfg.DnsUdpTcpOnly = r.Mode == "dns-udptcp"
		cfg.DnsTxtMode = r.Mode == "txt"
		cfg.ProbeDomains = nil
		cfg.TargetType = ""
		name := cfg.TargetDomain
		if cfg.DnsTxtMode {
			name = cfg.DnsTxtDomain
		}
		if err := engine.ValidateSNI(name); err != nil {
			return nil, fmt.Errorf("DNS domain: %w", err)
		}
	default:
		return nil, fmt.Errorf("unknown scan mode")
	}
	for _, domain := range cfg.ProbeDomains {
		if err := engine.ValidateSNI(domain); err != nil {
			return nil, err
		}
	}
	// Android scans always stream. CountTotal only schedules optional background work.
	cfg.Streaming, cfg.StreamingAuto = true, false
	return cfg, nil
}

// Start validates and schedules work; it never blocks on the network.
func (s *Scanner) Start(raw string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.current.Busy || s.speedCancel != nil {
		return fmt.Errorf("finish the current scan or speed test first")
	}
	r := request{Options: engine.DefaultConfig()}
	if err := json.Unmarshal([]byte(raw), &r); err != nil {
		return err
	}
	cfg, err := buildConfig(r)
	if err != nil {
		return err
	}
	run := time.Now().UTC().Format("20060102-150405.000000000")
	dir := filepath.Join(s.root, "runs", run)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	input := filepath.Join(dir, "targets.txt")
	if r.InputPath != "" {
		if !inside(s.root, r.InputPath) {
			return fmt.Errorf("import the input into app storage first")
		}
		src, err := os.Open(r.InputPath)
		if err != nil {
			return err
		}
		defer src.Close()
		dst, err := os.Create(input)
		if err != nil {
			return err
		}
		_, copyErr := io.Copy(dst, src)
		closeErr := dst.Close()
		if copyErr != nil {
			return copyErr
		}
		if closeErr != nil {
			return closeErr
		}
	} else {
		if strings.TrimSpace(r.Targets) == "" {
			return fmt.Errorf("add targets or import a file")
		}
		if err := os.WriteFile(input, []byte(r.Targets), 0600); err != nil {
			return err
		}
	}
	if err := engine.ValidateTargetFile(input, cfg.TargetType); err != nil {
		return err
	}
	key := sha256.Sum256([]byte(r.Mode + "/" + r.Provider + "/" + cfg.TargetType))
	cache := filepath.Join(s.root, "profiles", fmt.Sprintf("%x", key[:8]))
	if err := os.MkdirAll(cache, 0700); err != nil {
		return err
	}
	cfg.OutputDir, cfg.InputFile, cfg.CacheFile = dir, input, filepath.Join(cache, "last_passed.txt")
	if err := os.WriteFile(filepath.Join(dir, "config.json"), []byte(encode(cfg)), 0600); err != nil {
		return err
	}
	rows, err := os.Create(filepath.Join(dir, "results.jsonl"))
	if err != nil {
		return err
	}
	csvFile, err := os.Create(filepath.Join(dir, "results.csv"))
	if err != nil {
		rows.Close()
		return err
	}
	if s.rows != nil {
		s.rows.Close()
	}
	s.rows, s.csvFile, s.csv = rows, csvFile, csv.NewWriter(csvFile)
	s.csv.Write(csvHeader)
	s.index = nil
	s.config = cfg
	s.started = time.Now()
	s.stopRequested = false
	s.current = snapshot{Run: run, Mode: r.Mode, State: "starting", Busy: true, Counts: map[string]int{}}
	s.ready = make(chan struct{})
	handler := &handler{s: s, ready: s.ready}
	s.engine = engine.NewEngine(cfg, handler)
	go func() {
		s.engine.Start()
		s.mu.Lock()
		defer s.mu.Unlock()
		s.csv.Flush()
		if err := s.csv.Error(); err != nil {
			s.current.Error = "CSV export: " + err.Error()
		}
		s.csvFile.Close()
		s.current.Elapsed = time.Since(s.started).Seconds()
		s.current.Busy = false
		s.current.State = "completed"
		if s.stopRequested {
			s.current.State = "stopped"
		}
		if s.current.Error != "" {
			s.current.State = "failed"
		}
		os.WriteFile(filepath.Join(dir, "run.json"), []byte(encode(s.current)), 0600)
	}()
	return nil
}
func inside(root, path string) bool {
	rel, err := filepath.Rel(root, path)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) && !filepath.IsAbs(rel)
}
func (s *Scanner) Snapshot() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	st := s.current
	if st.Busy {
		st.Elapsed = time.Since(s.started).Seconds()
	}
	st.Rows = len(s.index)
	return encode(st)
}
func (s *Scanner) Results(offset, limit int) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if offset < 0 || limit < 1 || limit > 250 {
		return "", fmt.Errorf("use a page of 1–250 results")
	}
	rows := make([]json.RawMessage, 0, limit)
	for i := offset; i < len(s.index) && len(rows) < limit; i++ {
		row, err := s.readRow(i)
		if err != nil {
			return "", err
		}
		rows = append(rows, row)
	}
	return encode(rows), nil
}

// query is the desktop Results filter: tab, search, DNS protocol and sort.
type query struct {
	Tab      string `json:"tab"`      // all | ok | dead | poisoned | hijacked | tunnel
	Search   string `json:"search"`   // case-insensitive substring
	Protocol string `json:"protocol"` // "" = any; else UDP, TCP, DoT, DoH
	SortBy   string `json:"sortBy"`   // seq | latency | target | port | status
	Desc     bool   `json:"desc"`
	Offset   int    `json:"offset"`
	Limit    int    `json:"limit"`
}

// queryRow is a stored result plus the fields the UI filters and acts on;
// Seq is what TestSpeed takes.
type queryRow struct {
	engine.ScanResult
	Seq      int
	Category string
	Hijacked bool
}

func (q query) matches(r *queryRow) bool {
	switch q.Tab {
	case "ok", "dead", "poisoned":
		if r.Category != q.Tab {
			return false
		}
	case "hijacked":
		if !r.Hijacked {
			return false
		}
	case "tunnel":
		if !r.TunnelReady {
			return false
		}
	}
	if q.Protocol != "" && !strings.HasPrefix(r.DnsProtocol, q.Protocol) {
		return false
	}
	if q.Search != "" {
		hay := strings.ToLower(r.Label + " " + r.URL + " " + r.ResolvedIP + " " + r.DnsAnswer + " " + r.Error + " " + r.DnsProtocol + " " + strconv.Itoa(r.Port))
		return strings.Contains(hay, strings.ToLower(q.Search))
	}
	return true
}

// filter reads the stored results without holding the lock, so a query never
// stalls a running scan's writers.
// ponytail: reads every stored row per query; keep an in-memory summary if huge runs feel slow.
func (s *Scanner) filter(q query) ([]queryRow, map[string]int, error) {
	s.mu.Lock()
	file, n := s.rows, len(s.index)
	counts := make(map[string]int, len(s.current.Counts))
	for k, v := range s.current.Counts {
		counts[k] = v
	}
	s.mu.Unlock()
	out := []queryRow{}
	if file == nil {
		return out, counts, nil
	}
	reader := bufio.NewReader(io.NewSectionReader(file, 0, 1<<62))
	for seq := 1; seq <= n; seq++ {
		line, err := reader.ReadBytes('\n')
		if err != nil {
			return nil, nil, err
		}
		row := queryRow{Seq: seq}
		if err = json.Unmarshal(line, &row.ScanResult); err != nil {
			return nil, nil, err
		}
		row.Category, row.Hijacked = category(&row.ScanResult), hijacked(&row.ScanResult)
		if q.matches(&row) {
			out = append(out, row)
		}
	}
	less := func(a, b *queryRow) bool { return a.Seq < b.Seq }
	switch q.SortBy {
	case "latency": // failed probes have no meaningful latency; keep them last
		less = func(a, b *queryRow) bool {
			if (a.Error == "") != (b.Error == "") {
				return a.Error == ""
			}
			return a.LatencyMs < b.LatencyMs
		}
	case "target":
		less = func(a, b *queryRow) bool { return a.Label < b.Label }
	case "port":
		less = func(a, b *queryRow) bool { return a.Port < b.Port }
	case "status":
		less = func(a, b *queryRow) bool { return a.Status < b.Status }
	}
	sort.SliceStable(out, func(i, j int) bool {
		if q.Desc {
			return less(&out[j], &out[i])
		}
		return less(&out[i], &out[j])
	})
	return out, counts, nil
}

// Query returns {"rows","total","counts"} for one page (1–250) of filtered results.
func (s *Scanner) Query(raw string) (string, error) {
	var q query
	if err := json.Unmarshal([]byte(raw), &q); err != nil {
		return "", err
	}
	if q.Offset < 0 || q.Limit < 1 || q.Limit > 250 {
		return "", fmt.Errorf("use a page of 1–250 results")
	}
	rows, counts, err := s.filter(q)
	if err != nil {
		return "", err
	}
	start := min(q.Offset, len(rows))
	end := min(start+q.Limit, len(rows))
	return encode(map[string]any{"rows": rows[start:end], "total": len(rows), "counts": counts}), nil
}

// Export writes every result matching the query (paging ignored) into the
// shown run's folder, so it is listed in Reports, and returns its path.
func (s *Scanner) Export(raw string) (string, error) {
	var q query
	if err := json.Unmarshal([]byte(raw), &q); err != nil {
		return "", err
	}
	s.mu.Lock()
	run := s.current.Run
	s.mu.Unlock()
	if run == "" {
		return "", fmt.Errorf("run or load a scan first")
	}
	rows, _, err := s.filter(q)
	if err != nil {
		return "", err
	}
	tab := q.Tab
	if tab == "" {
		tab = "all"
	}
	path := filepath.Join(s.root, "runs", run, fmt.Sprintf("export_%s_%s.csv", filepath.Base(tab), time.Now().Format("20060102_150405")))
	f, err := os.Create(path)
	if err != nil {
		return "", err
	}
	w := csv.NewWriter(f)
	w.Write(csvHeader)
	for i := range rows {
		w.Write(csvRecord(&rows[i].ScanResult))
	}
	w.Flush()
	if err = w.Error(); err == nil {
		err = f.Close()
	} else {
		f.Close()
	}
	if err != nil {
		os.Remove(path)
		return "", err
	}
	return path, nil
}

var csvHeader = []string{"label", "url", "ip", "port", "status", "latency_ms", "error", "protocol", "poisoned", "hijacked", "tunnel_ready", "service_passed", "service_total", "service_summary"}

func csvRecord(r *engine.ScanResult) []string {
	return []string{r.Label, r.URL, r.ResolvedIP, strconv.Itoa(r.Port), strconv.Itoa(r.Status), strconv.Itoa(r.LatencyMs), r.Error, r.DnsProtocol, strconv.FormatBool(r.IsPoisoned), strconv.FormatBool(hijacked(r)), strconv.FormatBool(r.TunnelReady), strconv.Itoa(r.ServicePassed), strconv.Itoa(r.ServiceTotal), r.ServiceSummary}
}

// reportKind labels run-folder files like the desktop Reports page; "" hides one.
func reportKind(name string) string {
	for _, k := range [][2]string{
		{"reachable_", "Reachable"}, {"tunnel_ready_", "Tunnel-ready resolvers"}, {"poisoned_dns_", "Poisoned DNS"},
		{"hijacked_dns_", "Hijacked DNS"}, {"raw_ip_dump_", "Raw IP dump"}, {"dns_headers_", "DNS headers"},
		{"full_log_", "Full log"}, {"debug_count_", "Counts"}, {"results.csv", "All results (CSV)"}, {"export_", "Filtered export (CSV)"},
	} {
		if strings.HasPrefix(name, k[0]) {
			return k[1]
		}
	}
	return ""
}

func (s *Scanner) readRow(i int) ([]byte, error) {
	if s.rows == nil || i < 0 || i >= len(s.index) {
		return nil, fmt.Errorf("select a result")
	}
	reader := bufio.NewReader(io.NewSectionReader(s.rows, s.index[i], 1<<20))
	return reader.ReadBytes('\n')
}
func (s *Scanner) Pause() {
	s.mu.Lock()
	e, busy := s.engine, s.current.Busy
	s.mu.Unlock()
	if busy && e != nil {
		e.Pause()
	}
}
func (s *Scanner) Resume() {
	s.mu.Lock()
	e, busy := s.engine, s.current.Busy
	s.mu.Unlock()
	if busy && e != nil {
		e.Resume()
	}
}
func (s *Scanner) Stop() {
	s.mu.Lock()
	e, busy, ready := s.engine, s.current.Busy, s.ready
	if busy {
		s.stopRequested = true
	}
	s.mu.Unlock()
	if busy && e != nil {
		go func() { <-ready; e.Stop() }()
	}
}
func (s *Scanner) CancelSpeedTest() {
	s.mu.Lock()
	cancel := s.speedCancel
	s.mu.Unlock()
	if cancel != nil {
		cancel()
	}
}
func (s *Scanner) TestSpeed(run string, seq int, downloadURL string, seconds, sizeMB int) (string, error) {
	if seconds < 1 || seconds > 60 || sizeMB < 1 || sizeMB > 1024 {
		return "", fmt.Errorf("use 1-60 seconds and 1-1024 MB")
	}
	if strings.TrimSpace(downloadURL) == "" {
		return "", fmt.Errorf("enter a download URL")
	}
	s.mu.Lock()
	if run != s.current.Run || s.speedCancel != nil {
		s.mu.Unlock()
		return "", fmt.Errorf("select a result from this run; only one speed test at a time")
	}
	b, err := s.readRow(seq - 1)
	if err != nil {
		s.mu.Unlock()
		return "", err
	}
	var row engine.ScanResult
	if err = json.Unmarshal(b, &row); err != nil {
		s.mu.Unlock()
		return "", err
	}
	if row.Error != "" || row.DnsProtocol != "" || row.IsPoisoned {
		s.mu.Unlock()
		return "", fmt.Errorf("select a reachable IP or proxy")
	}
	kind, forged := s.current.Mode, s.config.SpoofedSNI
	if kind != "sni" && kind != "http-proxy" && kind != "socks-proxy" {
		kind = ""
	}
	cfg := *s.config
	ctx, cancel := context.WithCancel(context.Background())
	s.speedCancel = cancel
	s.mu.Unlock()
	defer func() { cancel(); s.mu.Lock(); s.speedCancel = nil; s.mu.Unlock() }()
	host := row.ResolvedIP
	if host == "" {
		host = row.Label // edge domains and hostname proxies may have no resolved IP
	}
	target := engine.Target{Host: host, Port: row.Port}
	if u, err := url.Parse(row.URL); err == nil {
		target.Scheme = u.Scheme
		target.ExplicitScheme = kind == "http-proxy" && u.Scheme == "https"
		if u.User != nil {
			target.Username = u.User.Username()
			target.Password, _ = u.User.Password()
		}
	}
	result, err := engine.MeasureDownloadWithDPI(ctx, target, kind, forged, downloadURL, seconds, int64(sizeMB)<<20, &cfg)
	if err != nil {
		return "", err
	}
	return encode(result), nil
}

func (s *Scanner) Reports() (string, error) {
	root := filepath.Join(s.root, "runs")
	entries, err := os.ReadDir(root)
	if os.IsNotExist(err) {
		return "[]", nil
	}
	if err != nil {
		return "", err
	}
	files := []map[string]any{}
	for i := len(entries) - 1; i >= 0; i-- {
		entry := entries[i]
		if !entry.IsDir() {
			continue
		}
		children, _ := os.ReadDir(filepath.Join(root, entry.Name()))
		for _, child := range children {
			kind := reportKind(child.Name())
			if child.IsDir() || kind == "" {
				continue
			}
			info, _ := child.Info()
			if info != nil {
				files = append(files, map[string]any{"run": entry.Name(), "name": child.Name(), "kind": kind, "path": filepath.Join(root, entry.Name(), child.Name()), "bytes": info.Size()})
			}
		}
	}
	return encode(files), nil
}

// LoadRun restores indexed results without replaying any network probes.
func (s *Scanner) LoadRun(run string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.current.Busy || s.speedCancel != nil {
		return fmt.Errorf("finish the current scan or speed test first")
	}
	if filepath.Base(run) != run || run == "." || run == ".." {
		return fmt.Errorf("select a saved run")
	}
	dir := filepath.Join(s.root, "runs", run)
	meta, err := os.ReadFile(filepath.Join(dir, "run.json"))
	if err != nil {
		return err
	}
	var status snapshot
	if err = json.Unmarshal(meta, &status); err != nil {
		return err
	}
	config, err := os.ReadFile(filepath.Join(dir, "config.json"))
	if err != nil {
		return err
	}
	var cfg engine.ScanConfig
	if err = json.Unmarshal(config, &cfg); err != nil {
		return err
	}
	file, err := os.Open(filepath.Join(dir, "results.jsonl"))
	if err != nil {
		return err
	}
	reader := bufio.NewReader(file)
	index := []int64{}
	offset := int64(0)
	counts := map[string]int{} // recounted so runs saved before counts existed still filter
	for {
		row, readErr := reader.ReadBytes('\n')
		if len(row) > 0 {
			var result engine.ScanResult
			if json.Unmarshal(row, &result) != nil {
				file.Close()
				return fmt.Errorf("saved result is incomplete")
			}
			countResult(counts, &result)
			index = append(index, offset)
			offset += int64(len(row))
		}
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			file.Close()
			return readErr
		}
	}
	if s.rows != nil {
		s.rows.Close()
	}
	s.rows, s.index, s.config = file, index, &cfg
	status.Busy = false
	status.Run = run
	status.Counts = counts
	s.current = status
	return nil
}

type handler struct {
	s     *Scanner
	ready chan struct{}
	once  sync.Once
}

func (h *handler) OnResult(result *engine.ScanResult) {
	s := h.s
	s.mu.Lock()
	defer s.mu.Unlock()
	offset, err := s.rows.Seek(0, io.SeekCurrent)
	if err == nil {
		b, _ := json.Marshal(result)
		_, err = s.rows.Write(append(b, '\n'))
		if err == nil {
			s.index = append(s.index, offset)
		}
	}
	if err != nil {
		s.current.Error = "Result storage: " + err.Error()
	}
	s.csv.Write(csvRecord(result))
	countResult(s.current.Counts, result)
	if result.Error == "" && !result.IsPoisoned {
		s.current.Open++
	} else {
		s.current.Dead++
	}
}
func (h *handler) OnProgress(done, total int) {
	h.s.mu.Lock()
	h.s.current.Done, h.s.current.Total = done, total
	h.s.mu.Unlock()
}
func (h *handler) OnStateChange(state string) {
	h.once.Do(func() { close(h.ready) })
	h.s.mu.Lock()
	defer h.s.mu.Unlock()
	if strings.HasPrefix(state, "FATAL:") || strings.HasPrefix(state, "ERROR:") {
		h.s.current.Error = state
	} else {
		h.s.current.State = strings.ToLower(state)
	}
}
func (h *handler) OnComplete(open, dead, total int) {
	h.s.mu.Lock()
	h.s.current.Open, h.s.current.Total = open, total
	h.s.mu.Unlock()
}
