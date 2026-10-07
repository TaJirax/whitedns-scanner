package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// RunInfo describes one scan's folder: <output>/<mode>/<date time>/.
type RunInfo struct {
	TransportSaved     bool           `json:"transportSaved,omitempty"`
	AntiDPI            bool           `json:"antiDpi,omitempty"`
	DPIFragmentSize    int            `json:"dpiFragmentSize,omitempty"`
	DPIFragmentDelayMs int            `json:"dpiFragmentDelayMs,omitempty"`
	SpoofedSNI         string         `json:"spoofedSni,omitempty"`
	EdgeProvider       string         `json:"edgeProvider,omitempty"`
	TargetType         string         `json:"targetType,omitempty"`
	Dir                string         `json:"dir"`
	Mode               string         `json:"mode"`
	Started            time.Time      `json:"started"`
	Finished           time.Time      `json:"finished"`
	State              string         `json:"state"` // running | completed | stopped | failed
	Done               int            `json:"done"`
	Total              int            `json:"total"`
	Counts             map[string]int `json:"counts"`
	Message            string         `json:"message"`
	Targets            string         `json:"targets"` // where the targets came from
	Files              []FileInfo     `json:"files,omitempty"`
	HasResult          bool           `json:"hasResults,omitempty"`
}

type FileInfo struct {
	Name  string `json:"name"`
	Path  string `json:"path"`
	Kind  string `json:"kind"`
	Size  int64  `json:"size"`
	Lines int    `json:"lines"`
}

const runInfoFile = "run.json"

// reportKinds labels the files the engine and the app write into a run folder.
var reportKinds = []struct{ prefix, label string }{
	{"reachable_", "Reachable"},
	{"tunnel_ready_", "Tunnel-ready resolvers"},
	{"poisoned_dns_", "Poisoned DNS"},
	{"hijacked_dns_", "Hijacked DNS"},
	{"raw_ip_dump_", "Raw IP dump"},
	{"dns_headers_", "DNS headers"},
	{"full_log_", "Full log"},
	{"debug_count_", "Counts"},
	{"clean_ips.txt", "Clean IPs for fronting"},
	{"results.csv", "All results (CSV)"},
	{"targets.txt", "Targets scanned"},
}

func kindOf(name string) (string, int) {
	for i, k := range reportKinds {
		if strings.HasPrefix(name, k.prefix) {
			return k.label, i
		}
	}
	return "", -1
}

func writeRunInfo(info RunInfo) error {
	info.Files = nil
	raw, err := json.MarshalIndent(info, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(info.Dir, runInfoFile), raw, 0o644)
}

func readRunInfo(dir, mode string) RunInfo {
	info := RunInfo{Dir: dir, Mode: mode, State: "completed"}
	if raw, err := os.ReadFile(filepath.Join(dir, runInfoFile)); err == nil {
		_ = json.Unmarshal(raw, &info)
		info.Dir, info.Mode = dir, mode
	} else if t, err := time.ParseInLocation("2006-01-02 15-04-05", strings.SplitN(filepath.Base(dir), " (", 2)[0], time.Local); err == nil {
		info.Started = t
	}
	return info
}

// listRuns returns every run under the output dir, newest first.
func listRuns(outputDir string) []RunInfo {
	var runs []RunInfo
	for mode, folder := range modeFolders {
		entries, err := os.ReadDir(filepath.Join(outputDir, folder))
		if err != nil {
			continue
		}
		for _, e := range entries {
			if !e.IsDir() {
				continue
			}
			info := readRunInfo(filepath.Join(outputDir, folder, e.Name()), mode)
			info.Files, info.HasResult = runFiles(info.Dir)
			if len(info.Files) == 0 && info.State != "running" {
				continue // an empty folder left by a scan that never started
			}
			runs = append(runs, info)
		}
	}
	sort.Slice(runs, func(i, j int) bool { return runs[i].Started.After(runs[j].Started) })
	return runs
}

func runFiles(dir string) ([]FileInfo, bool) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, false
	}
	type ranked struct {
		FileInfo
		rank int
	}
	var files []ranked
	hasResults := false
	for _, e := range entries {
		if e.IsDir() || e.Name() == runInfoFile {
			continue
		}
		kind, rank := kindOf(e.Name())
		if rank < 0 {
			continue
		}
		fi, _ := e.Info()
		path := filepath.Join(dir, e.Name())
		files = append(files, ranked{FileInfo{Name: e.Name(), Path: path, Kind: kind, Size: fi.Size(), Lines: countLines(path)}, rank})
		hasResults = hasResults || e.Name() == "results.csv"
	}
	sort.Slice(files, func(i, j int) bool { return files[i].rank < files[j].rank })
	out := make([]FileInfo, len(files))
	for i, f := range files {
		out[i] = f.FileInfo
	}
	return out, hasResults
}

// countLines counts non-empty lines; capped so huge logs stay cheap to list.
func countLines(path string) int {
	f, err := os.Open(path)
	if err != nil {
		return 0
	}
	defer f.Close()
	sc := bufio.NewScanner(io.LimitReader(f, 32<<20))
	sc.Buffer(make([]byte, 64*1024), 1<<20)
	n := 0
	for sc.Scan() {
		if strings.TrimSpace(sc.Text()) != "" {
			n++
		}
	}
	return n
}

// insideDir reports whether path is dir or lies under it, so the UI can only
// read or open files in the output folder.
func insideDir(dir, path string) bool {
	rel, err := filepath.Rel(filepath.Clean(dir), filepath.Clean(path))
	return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) && !filepath.IsAbs(rel)
}

const maxReportView = 2 << 20 // 2 MB shown in-app; the full file opens externally

func readReport(outputDir, path string) (string, error) {
	if !insideDir(outputDir, path) {
		return "", fmt.Errorf("that file is outside the output folder")
	}
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, maxReportView+1))
	if err != nil {
		return "", err
	}
	if len(raw) > maxReportView {
		return string(raw[:maxReportView]) + "\n\n… (file continues; open it to see everything)", nil
	}
	return string(raw), nil
}
