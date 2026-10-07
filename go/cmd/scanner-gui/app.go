package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/wailsapp/wails/v2/pkg/runtime"

	"reachability-scanner/engine"
)

// Stats is the live summary the UI redraws a few times per second.
type Stats struct {
	EdgeProvider string         `json:"edgeProvider"`
	TargetType   string         `json:"targetType"`
	State        string         `json:"state"` // IDLE | RUNNING | PAUSED | STOPPED
	Mode         string         `json:"mode"`  // mode of the scan shown (live or loaded)
	Done         int            `json:"done"`
	Total        int            `json:"total"`
	Counts       map[string]int `json:"counts"`
	RatePerS     float64        `json:"ratePerS"`
	ElapsedS     float64        `json:"elapsedS"`
	EtaS         float64        `json:"etaS"`
	Recent       []Row          `json:"recent"` // newest first
	Log          []LogLine      `json:"log"`    // oldest first
	RunDir       string         `json:"runDir"`
	Message      string         `json:"message"`
	Viewing      string         `json:"viewing"` // run folder loaded from Reports; "" = live scan
}

const recentRows = 14

// LogLine is one entry of the live scan log.
type LogLine struct {
	Seq   int    `json:"seq"`
	At    string `json:"at"`    // local time, HH:MM:SS
	Level string `json:"level"` // info | ok | fail | error
	Text  string `json:"text"`
}

// logKeep lines are kept and sent with every stats push (4x per second).
const logKeep = 120

type App struct {
	ctx         context.Context
	speedCancel context.CancelFunc
	speedBusy   bool

	mu            sync.Mutex
	settings      Settings
	eng           *engine.Engine
	run           RunInfo // the scan in progress or last finished
	viewing       string  // past run loaded into Results
	state         string
	busy          bool // a scan is running or still saving its results
	stopRequested bool
	message       string
	started       time.Time
	finished      time.Time
	recent        []Row
	logs          []LogLine
	logSeq        int
	logPct        int // last progress milestone logged, in tens of percent
	rate          float64

	done, total atomic.Int64
	results     *store
}

func NewApp() *App {
	return &App{settings: loadSettings(), state: "IDLE", results: newStore()}
}

func (a *App) startup(ctx context.Context) { a.ctx = ctx }

func (a *App) GetEdgeProviders() []engine.EdgeProvider { return engine.EdgeProviders() }

func (a *App) GetScanModes() []engine.ScanMode { return engine.ScanModes() }

// SearchASNs lists the bundled ASNs (the Android app's set) matching query
// that have ranges in family: "ipv4", "ipv6" or "both".
func (a *App) SearchASNs(query, family string) ([]engine.ASNSummary, error) {
	return engine.SearchASNs(query, family)
}

// ExportASNs is the TUI's "Export ASN IPs": every IP of the selected ASNs'
// ranges in family, saved to a file the user picks (default: the output folder).
func (a *App) ExportASNs(asns []string, family string) (string, error) {
	ranges, err := engine.ASNRanges(asns, family)
	if err != nil {
		return "", err
	}
	path, err := runtime.SaveFileDialog(a.ctx, runtime.SaveDialogOptions{
		Title:            "Export ASN IPs",
		DefaultDirectory: a.GetSettings().OutputDir,
		DefaultFilename:  fmt.Sprintf("asn_ips-%s.txt", time.Now().Format("20060102-150405")),
		Filters:          []runtime.FileFilter{{DisplayName: "Text files (*.txt)", Pattern: "*.txt"}},
	})
	if err != nil || path == "" {
		return "", err
	}
	f, err := os.Create(path)
	if err != nil {
		return "", err
	}
	n, err := engine.WriteASNExport(f, len(asns), ranges)
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		os.Remove(path)
		return "", err
	}
	return fmt.Sprintf("Exported %d IPs from %d ASNs to %s", n, len(asns), path), nil
}

// ---- settings -------------------------------------------------------------

func (a *App) GetSettings() Settings {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.settings
}

func (a *App) SaveSettings(s Settings) error {
	a.mu.Lock()
	a.settings = s
	a.mu.Unlock()
	return saveSettings(s)
}

func (a *App) ResetSettings() Settings {
	old := a.GetSettings()
	s := defaultSettings()
	s.Theme, s.Targets, s.Accent = old.Theme, old.Targets, old.Accent // keep the look and the target lists
	_ = a.SaveSettings(s)
	return s
}

func (a *App) PickInputFile() string {
	p, _ := runtime.OpenFileDialog(a.ctx, runtime.OpenDialogOptions{
		Title:   "Choose targets file",
		Filters: []runtime.FileFilter{{DisplayName: "Text files (*.txt)", Pattern: "*.txt"}, {DisplayName: "All files", Pattern: "*.*"}},
	})
	return p
}

func (a *App) PickOutputDir() string {
	p, _ := runtime.OpenDirectoryDialog(a.ctx, runtime.OpenDialogOptions{Title: "Choose output folder"})
	return p
}

// OpenPath opens a folder or report in the platform's default app. Only
// paths inside the output folder are allowed.
func (a *App) OpenPath(path string) error {
	out := a.GetSettings().OutputDir
	if path == "" {
		path = out
	}
	if !insideDir(out, path) {
		return fmt.Errorf("that path is outside the output folder")
	}
	if err := os.MkdirAll(out, 0o755); err != nil {
		return err
	}
	absolute, err := filepath.Abs(path)
	if err != nil {
		return err
	}
	cmd := openPathCommand(absolute)
	if err := cmd.Start(); err != nil {
		return err
	}
	go func() { _ = cmd.Wait() }()
	return nil
}

// ---- scan control ---------------------------------------------------------

func (a *App) StartScan(mode string, s Settings) error {
	a.mu.Lock()
	if a.busy {
		a.mu.Unlock()
		return fmt.Errorf("a scan is already running")
	}
	a.busy = true // held until the run folder is complete
	a.mu.Unlock()
	started := false
	defer func() {
		if !started {
			a.mu.Lock()
			a.busy = false
			a.mu.Unlock()
		}
	}()

	if err := a.SaveSettings(s); err != nil {
		return fmt.Errorf("cannot save settings: %v", err)
	}
	if strings.TrimSpace(s.OutputDir) == "" {
		return fmt.Errorf("choose an output folder in Settings")
	}
	now := time.Now()
	runDir, err := newRunDir(s.OutputDir, mode, now)
	if err != nil {
		return fmt.Errorf("cannot create the run folder: %v", err)
	}
	cfg, err := s.toScanConfig(mode, runDir)
	if err != nil {
		_ = os.RemoveAll(runDir) // nothing was scanned; leave no empty folder
		return err
	}

	selectedInput := s.Targets[mode].selectedInput()
	targets := "pasted list"
	if strings.TrimSpace(selectedInput.TargetsText) == "" {
		targets = selectedInput.InputFile
	}
	if n := len(selectedInput.ASNs); n > 0 {
		names := make([]string, 0, n)
		for _, p := range selectedInput.ASNs {
			names = append(names, p.ASN)
		}
		if targets != "" {
			targets += " + "
		}
		targets += "ASN " + strings.Join(names, ", ")
	}
	run := RunInfo{EdgeProvider: cfg.EdgeProvider, TargetType: cfg.TargetType, Dir: runDir, Mode: mode, Started: now, State: "running", Targets: targets}
	run.TransportSaved, run.AntiDPI, run.DPIFragmentSize, run.DPIFragmentDelayMs, run.SpoofedSNI = true, cfg.AntiDPI, cfg.DPIFragmentSize, cfg.DPIFragmentDelayMs, cfg.SpoofedSNI
	_ = writeRunInfo(run)

	a.results.reset()
	a.done.Store(0)
	a.total.Store(0)
	engineReady := make(chan struct{})
	eng := engine.NewEngine(cfg, &guiHandler{app: a, started: engineReady})

	a.mu.Lock()
	a.eng, a.run, a.viewing, a.state, a.message = eng, run, "", "RUNNING", ""
	a.stopRequested = false
	a.started, a.finished, a.recent, a.rate = now, time.Time{}, nil, 0
	a.logs, a.logPct = nil, 0
	a.addLogLocked("info", "Scan started with targets from the "+targets)
	a.mu.Unlock()

	started = true
	go func() {
		eng.Start() // blocks until the scan ends; the engine writes its reports into runDir
		a.finishRun()
		a.emitStats()
		if a.ctx != nil {
			runtime.EventsEmit(a.ctx, "scan:done", a.GetStats())
		}
	}()
	<-engineReady // Stop is safe as soon as StartScan returns.
	go a.statsLoop()
	return nil
}

// finishRun saves every result next to the engine's reports and records how
// the run ended, so the Reports page can list and reload it later.
func (a *App) finishRun() {
	a.mu.Lock()
	if a.state != "STOPPED" {
		a.state = "STOPPED" // the engine returns early on a fatal setup error
	}
	if a.finished.IsZero() {
		a.finished = time.Now()
	}
	run := a.run
	run.Finished = a.finished
	run.Done, run.Total = int(a.done.Load()), int(a.total.Load())
	run.Counts = a.results.snapshotCounts()
	run.Message = a.message
	switch {
	case strings.HasPrefix(a.message, "FATAL"), strings.HasPrefix(a.message, "ERROR"):
		run.State = "failed"
	case a.stopRequested || (run.Total > 0 && run.Done < run.Total):
		run.State = "stopped"
	default:
		run.State = "completed"
	}
	a.run = run
	a.mu.Unlock()

	if ips := a.results.cleanIPs(); ips != "" {
		_ = os.WriteFile(filepath.Join(run.Dir, "clean_ips.txt"), []byte(ips), 0o644)
	}
	if _, err := writeRowsCSV(filepath.Join(run.Dir, "results.csv"), a.results.all()); err != nil {
		run.State = "failed"
		run.Message = fmt.Sprintf("ERROR: could not save results.csv: %v", err)
		a.mu.Lock()
		a.run, a.message = run, run.Message
		a.mu.Unlock()
	}
	if err := writeRunInfo(run); err != nil {
		a.mu.Lock()
		a.run.State = "failed"
		a.message = fmt.Sprintf("ERROR: could not save run metadata: %v", err)
		a.mu.Unlock()
	}
	a.mu.Lock()
	a.busy = false
	a.mu.Unlock()
}

func (a *App) setMessage(m string) {
	a.mu.Lock()
	a.message = m
	a.mu.Unlock()
}

func (a *App) PauseScan()  { a.withEngine((*engine.Engine).Pause) }
func (a *App) ResumeScan() { a.withEngine((*engine.Engine).Resume) }
func (a *App) StopScan() {
	a.mu.Lock()
	eng := a.eng
	if a.busy && eng != nil && a.state != "STOPPED" {
		a.stopRequested = true
		a.addLogLocked("info", "Stopping: finishing probes in flight and saving reports")
	}
	a.mu.Unlock()
	if eng != nil {
		eng.Stop()
	}
}

func (a *App) withEngine(f func(*engine.Engine)) {
	a.mu.Lock()
	eng, active := a.eng, a.state == "RUNNING" || a.state == "PAUSED"
	a.mu.Unlock()
	if eng != nil && active {
		f(eng)
	}
}

// ---- results & reports ----------------------------------------------------

func (a *App) QueryResults(q Query) Page { return a.results.query(q) }

// CleanIPs returns the passed endpoints shown in Results as ip:port lines,
// fastest first, ready to paste into Worker / CDN configs.
func (a *App) CleanIPs() string { return a.results.cleanIPs() }

// DeleteResults removes the rows with the given Seq numbers or, when none are
// given, every row matching q. The run's results.csv and tallies are rewritten
// so deleted results stay gone when the run is loaded again.
func (a *App) DeleteResults(q Query, seqs []int) (int, error) {
	a.mu.Lock()
	busy, run := a.busy, a.run
	a.mu.Unlock()
	if busy {
		return 0, fmt.Errorf("wait for the scan to finish before deleting results")
	}
	match := q.matches
	if len(seqs) > 0 {
		chosen := make(map[int]bool, len(seqs))
		for _, seq := range seqs {
			chosen[seq] = true
		}
		match = func(r *Row) bool { return chosen[r.Seq] }
	}
	n := a.results.remove(match)
	if n > 0 && run.Dir != "" {
		if _, err := os.Stat(run.Dir); err == nil {
			if _, err := writeRowsCSV(filepath.Join(run.Dir, "results.csv"), a.results.all()); err != nil {
				return n, fmt.Errorf("deleted %d results, but results.csv could not be updated: %v", n, err)
			}
			run.Counts = a.results.snapshotCounts()
			_ = writeRunInfo(run)
			a.mu.Lock()
			if a.run.Dir == run.Dir {
				a.run.Counts = run.Counts
			}
			a.mu.Unlock()
		}
	}
	a.emitStats()
	return n, nil
}

func (a *App) ExportResults(q Query) (string, error) {
	path, err := runtime.SaveFileDialog(a.ctx, runtime.SaveDialogOptions{
		Title:           "Export results",
		DefaultFilename: fmt.Sprintf("scan_%s_%s.csv", q.Tab, time.Now().Format("20060102_150405")),
		Filters:         []runtime.FileFilter{{DisplayName: "CSV (*.csv)", Pattern: "*.csv"}},
	})
	if err != nil || path == "" {
		return "", err
	}
	n, err := a.results.exportCSV(q, path)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("Exported %d rows to %s", n, path), nil
}

func (a *App) ListRuns() []RunInfo { return listRuns(a.GetSettings().OutputDir) }

func (a *App) ReadReport(path string) (string, error) {
	return readReport(a.GetSettings().OutputDir, path)
}

// LoadRun shows a past run's results.csv in the Results page.
func (a *App) LoadRun(dir string) (Stats, error) {
	out := a.GetSettings().OutputDir
	if !insideDir(out, dir) {
		return Stats{}, fmt.Errorf("that run is outside the output folder")
	}
	a.mu.Lock()
	busy := a.busy
	a.mu.Unlock()
	if busy {
		return Stats{}, fmt.Errorf("wait for the running scan to finish first")
	}
	mode := ""
	for m, folder := range modeFolders {
		if filepath.Base(filepath.Dir(dir)) == folder {
			mode = m
		}
	}
	if err := a.results.loadCSV(filepath.Join(dir, "results.csv")); err != nil {
		return Stats{}, fmt.Errorf("cannot load this run: %v", err)
	}
	a.mu.Lock()
	a.viewing, a.recent = dir, nil
	a.run = readRunInfo(dir, mode)
	a.mu.Unlock()
	return a.GetStats(), nil
}

// ---- live stats -----------------------------------------------------------

func (a *App) GetStats() Stats {
	a.mu.Lock()
	defer a.mu.Unlock()
	st := Stats{
		EdgeProvider: a.run.EdgeProvider, TargetType: a.run.TargetType, State: a.state, Mode: a.run.Mode, Done: int(a.done.Load()), Total: int(a.total.Load()),
		Counts: a.results.snapshotCounts(), RatePerS: a.rate, Recent: append([]Row(nil), a.recent...), Log: append([]LogLine(nil), a.logs...),
		RunDir: a.run.Dir, Message: a.message, Viewing: a.viewing,
	}
	if a.viewing != "" {
		st.Done, st.Total = a.run.Done, a.run.Total
	}
	if !a.started.IsZero() && a.viewing == "" {
		end := a.finished
		if end.IsZero() {
			end = time.Now()
		}
		st.ElapsedS = end.Sub(a.started).Seconds()
	}
	if a.rate > 0 && st.Total > st.Done && a.state == "RUNNING" {
		st.EtaS = float64(st.Total-st.Done) / a.rate
	}
	return st
}

// statsLoop pushes a summary 4x per second instead of one event per result,
// so a fast scan never floods the webview.
func (a *App) statsLoop() {
	t := time.NewTicker(250 * time.Millisecond)
	defer t.Stop()
	lastDone, lastAt := int64(0), time.Now()
	for range t.C {
		now, done := time.Now(), a.done.Load()
		inst := float64(done-lastDone) / now.Sub(lastAt).Seconds()
		lastDone, lastAt = done, now

		a.mu.Lock()
		if a.state == "RUNNING" {
			a.rate = 0.8*a.rate + 0.2*inst // smoothed so the ETA doesn't jump
		}
		running := a.state == "RUNNING" || a.state == "PAUSED"
		a.mu.Unlock()

		a.emitStats()
		if !running {
			return
		}
	}
}

func (a *App) emitStats() {
	if a.ctx != nil {
		runtime.EventsEmit(a.ctx, "scan:stats", a.GetStats())
	}
}

// guiHandler receives engine callbacks from many worker goroutines.
type guiHandler struct {
	app       *App
	started   chan struct{}
	startOnce sync.Once
}

func (h *guiHandler) OnResult(r *engine.ScanResult) {
	row := h.app.results.add(r)
	h.app.mu.Lock()
	h.app.recent = append([]Row{row}, h.app.recent...)
	if len(h.app.recent) > recentRows {
		h.app.recent = h.app.recent[:recentRows]
	}
	h.app.addLogLocked(resultLog(row))
	h.app.mu.Unlock()
}

func (h *guiHandler) OnProgress(done, total int) {
	h.app.done.Store(int64(done))
	h.app.total.Store(int64(total))
	if total <= 0 {
		return
	}
	if pct := done * 10 / total; done > 0 {
		h.app.mu.Lock()
		if pct > h.app.logPct {
			h.app.logPct = pct
			h.app.addLogLocked("info", fmt.Sprintf("%d%% done: %s of %s scanned, %s passed", pct*10, group(done), group(total), group(h.app.results.snapshotCounts()["ok"])))
		}
		h.app.mu.Unlock()
	}
}

// OnLog receives the engine's setup steps (engine.LogHandler).
func (h *guiHandler) OnLog(message string) {
	h.app.mu.Lock()
	h.app.addLogLocked("info", groupNumbers(message))
	h.app.mu.Unlock()
}

func (h *guiHandler) OnStateChange(state string) {
	h.app.mu.Lock()
	switch {
	case state == "RUNNING" || state == "PAUSED" || state == "STOPPED":
		if state == "PAUSED" {
			h.app.addLogLocked("info", "Paused")
		} else if state == "RUNNING" && h.app.state == "PAUSED" {
			h.app.addLogLocked("info", "Resumed")
		}
		h.app.state = state
		if state == "STOPPED" && h.app.finished.IsZero() {
			h.app.finished = time.Now()
		}
	case strings.HasPrefix(state, "FATAL") || strings.HasPrefix(state, "ERROR"):
		h.app.message = state
		h.app.addLogLocked("error", state)
	}
	h.app.mu.Unlock()
	if state == "RUNNING" && h.started != nil {
		h.startOnce.Do(func() { close(h.started) })
	}
}

func (h *guiHandler) OnComplete(open, dead, total int) {
	h.app.mu.Lock()
	if !strings.HasPrefix(h.app.message, "FATAL") && !strings.HasPrefix(h.app.message, "ERROR") {
		h.app.message = fmt.Sprintf("Finished: %d passed, %d failed. Reports are in the run folder.", open, dead)
	}
	h.app.addLogLocked("info", fmt.Sprintf("Finished: %s passed, %s failed of %s. Reports saved.", group(open), group(dead), group(total)))
	h.app.mu.Unlock()
}
