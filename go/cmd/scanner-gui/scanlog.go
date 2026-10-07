package main

import (
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// addLogLocked appends to the live scan log; a.mu must be held.
func (a *App) addLogLocked(level, text string) {
	a.logSeq++
	a.logs = append(a.logs, LogLine{Seq: a.logSeq, At: time.Now().Format("15:04:05"), Level: level, Text: text})
	if len(a.logs) > logKeep {
		a.logs = a.logs[len(a.logs)-logKeep:]
	}
}

// resultLog is the log line for one finished probe.
func resultLog(r Row) (level, text string) {
	who := r.IP
	if who == "" {
		who = r.Label
	}
	if r.Port > 0 && net.ParseIP(who) != nil {
		who = net.JoinHostPort(who, strconv.Itoa(r.Port))
	}
	if r.Protocol != "" {
		who += " " + r.Protocol
	}
	switch r.Category {
	case "ok":
		text = "Passed " + who
		if r.ServiceTotal > 0 {
			text += fmt.Sprintf(" · %d/%d service domains", r.ServicePassed, r.ServiceTotal)
		}
		return "ok", text + fmt.Sprintf(" · %d ms", r.LatencyMs)
	case "poisoned":
		return "fail", "Poisoned " + who + " · " + firstLine(r.Answer)
	}
	return "fail", "Failed " + who + " · " + firstLine(r.Error)
}

func firstLine(s string) string {
	s, _, _ = strings.Cut(strings.TrimSpace(s), "\n")
	if len(s) > 140 {
		s = s[:140] + "…"
	}
	return s
}

// group writes n with thousands separators: 2495462 -> 2,495,462.
func group(n int) string {
	s := strconv.Itoa(n)
	start := 0
	if n < 0 {
		start = 1
	}
	for i := len(s) - 3; i > start; i -= 3 {
		s = s[:i] + "," + s[i:]
	}
	return s
}

var longNumber = regexp.MustCompile(`\b\d{4,}\b`)

// groupNumbers groups the long numbers in an engine message.
func groupNumbers(s string) string {
	return longNumber.ReplaceAllStringFunc(s, func(d string) string {
		n, err := strconv.Atoi(d)
		if err != nil {
			return d
		}
		return group(n)
	})
}
