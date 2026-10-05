package main

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/wailsapp/wails/v2/pkg/runtime"

	"reachability-scanner/engine"
)

// Stats is the live scan summary the UI redraws a few times per second.
type Stats struct {
	State     string         `json:"state"` // IDLE | RUNNING | PAUSED | STOPPED
	Mode      string         `json:"mode"`
	Done      int            `json:"done"`
	Total     int            `json:"total"`
	Counts    map[string]int `json:"counts"`
	RatePerS  float64        `json:"ratePerS"`
	ElapsedS  float64        `json:"elapsedS"`
	EtaS      float64        `json:"etaS"`
	Recent    []Row          `json:"recent"` // newest first
	OutputDir string         `json:"outputDir"`
	Message   string         `json:"message"`
}

const recentRows = 12

type App struct {
	ctx context.Context

	mu       sync.Mutex
	settings Settings
	eng      *engine.Engine
	mode     string
	state    string
	message  string
	started  time.Time
	finished time.Time
	recent   []Row
	rate     float64

	done, total atomic.Int64
	results     *store
}

func NewApp() *App {
	return &App{settings: loadSettings(), state: "IDLE", results: newStore()}
}

func (a *App) startup(ctx context.Context) { a.ctx = ctx }

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
	s := defaultSettings()
	s.Theme = a.GetSettings().Theme // keep the look the user picked
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

func (a *App) OpenOutputDir() {
	if dir := a.GetSettings().OutputDir; dir != "" {
		_ = exec.Command("explorer", dir).Start()
	}
}

// ---- scan control ---------------------------------------------------------

func (a *App) StartScan(s Settings) error {
	a.mu.Lock()
	if a.state == "RUNNING" || a.state == "PAUSED" {
		a.mu.Unlock()
		return fmt.Errorf("a scan is already running")
	}
	a.mu.Unlock()

	if err := a.SaveSettings(s); err != nil {
		return fmt.Errorf("cannot save settings: %v", err)
	}
	cfg, err := s.toScanConfig()
	if err != nil {
		return err
	}

	a.results.reset()
	a.done.Store(0)
	a.total.Store(0)
	eng := engine.NewEngine(cfg, &guiHandler{app: a})

	a.mu.Lock()
	a.eng, a.mode, a.state, a.message = eng, s.Mode, "RUNNING", ""
	a.started, a.finished, a.recent, a.rate = time.Now(), time.Time{}, nil, 0
	a.mu.Unlock()

	go func() {
		eng.Start() // blocks until the scan ends; writes reports to the output dir
		a.mu.Lock()
		if a.state != "STOPPED" {
			a.state = "STOPPED" // the engine returns early on a fatal setup error
		}
		if a.finished.IsZero() {
			a.finished = time.Now()
		}
		a.mu.Unlock()
		a.emitStats()
		if a.ctx != nil {
			runtime.EventsEmit(a.ctx, "scan:done", a.GetStats())
		}
	}()
	go a.statsLoop()
	return nil
}

func (a *App) PauseScan()  { a.withEngine((*engine.Engine).Pause) }
func (a *App) ResumeScan() { a.withEngine((*engine.Engine).Resume) }
func (a *App) StopScan()   { a.withEngine((*engine.Engine).Stop) }

func (a *App) withEngine(f func(*engine.Engine)) {
	a.mu.Lock()
	eng := a.eng
	a.mu.Unlock()
	if eng != nil {
		f(eng)
	}
}

func (a *App) QueryResults(q Query) Page { return a.results.query(q) }

func (a *App) ExportResults(q Query) (string, error) {
	path, err := runtime.SaveFileDialog(a.ctx, runtime.SaveDialogOptions{
		Title:           "Export results",
		DefaultFilename: fmt.Sprintf("scan_%s_%s.csv", q.Tab, time.Now().Format("20060102_150405")),
		Filters:         []runtime.FileFilter{{DisplayName: "CSV (*.csv)", Pattern: "*.csv"}},
	})
	if err != nil || path == "" {
		return "", err
	}
	n, err := a.results.exportCSV(q, path, a.GetSettings().isDNS())
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("Exported %d rows to %s", n, path), nil
}

// ---- live stats -----------------------------------------------------------

func (a *App) GetStats() Stats {
	a.mu.Lock()
	defer a.mu.Unlock()
	st := Stats{
		State: a.state, Mode: a.mode, Done: int(a.done.Load()), Total: int(a.total.Load()),
		Counts: a.results.snapshotCounts(), RatePerS: a.rate,
		Recent: append([]Row(nil), a.recent...), OutputDir: a.settings.OutputDir, Message: a.message,
	}
	if !a.started.IsZero() {
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
type guiHandler struct{ app *App }

func (h *guiHandler) OnResult(r *engine.ScanResult) {
	row := h.app.results.add(r)
	h.app.mu.Lock()
	h.app.recent = append([]Row{row}, h.app.recent...)
	if len(h.app.recent) > recentRows {
		h.app.recent = h.app.recent[:recentRows]
	}
	h.app.mu.Unlock()
}

func (h *guiHandler) OnProgress(done, total int) {
	h.app.done.Store(int64(done))
	h.app.total.Store(int64(total))
}

func (h *guiHandler) OnStateChange(state string) {
	h.app.mu.Lock()
	switch {
	case state == "RUNNING" || state == "PAUSED" || state == "STOPPED":
		h.app.state = state
		if state == "STOPPED" && h.app.finished.IsZero() {
			h.app.finished = time.Now()
		}
	case strings.HasPrefix(state, "FATAL") || strings.HasPrefix(state, "ERROR"):
		h.app.message = state
	}
	h.app.mu.Unlock()
}

func (h *guiHandler) OnComplete(open, dead, total int) {
	h.app.mu.Lock()
	h.app.message = fmt.Sprintf("Finished: %d reachable, %d failed. Reports saved to %s", open, dead, h.app.settings.OutputDir)
	h.app.mu.Unlock()
}
