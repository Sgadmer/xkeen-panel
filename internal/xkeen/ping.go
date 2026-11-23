package xkeen

import (
	"sort"
	"strconv"
	"time"

	"xkeen-panel/internal/models"
)

// One number per server, measured in one place. Only the router measures,
// with the check of its own Xray core: a GET through the server on a fresh
// connection, timed to the answer. The pool workers run it every minute for
// their members; a full check runs the same check for every server. The
// panel keeps the last pingKeep results and shows their median, so one slow
// or lucky answer moves nothing, and the pools pick by that same number.
const pingKeep = 3

// pingWindow drops samples too old to describe the server now.
const pingWindow = 24 * time.Hour

// PingNoAnswer is the reason shown when the router's check got no answer.
const PingNoAnswer = "Сервер не ответил на проверку роутера"

// ApplyPing adds one measurement to the server and recomputes its number. A
// measurement not newer than the last one is ignored and reported false.
func ApplyPing(s *models.Server, ms int, reason string, at time.Time) bool {
	if at.IsZero() {
		at = time.Now()
	}
	if n := len(s.PingSamples); n > 0 && !at.After(s.PingSamples[n-1].At) {
		return false
	}
	if ms > 0 {
		reason = ""
	} else {
		ms = -1
		if reason == "" {
			reason = PingNoAnswer
		}
	}
	samples := append(append([]models.PingSample(nil), s.PingSamples...), models.PingSample{Ms: ms, At: at, Error: reason})
	if len(samples) > pingKeep {
		samples = samples[len(samples)-pingKeep:]
	}
	s.PingSamples, s.ProbeKind, s.LastChecked = samples, "https", at
	RecomputePing(s)
	return true
}

// RecomputePing derives what a server shows from its samples: no number while
// its last check failed or it could not load a page, otherwise the median of
// its recent answers.
func RecomputePing(s *models.Server) {
	n := len(s.PingSamples)
	if n == 0 {
		return
	}
	last := s.PingSamples[n-1]
	switch {
	case s.LoadError != "":
		s.Latency, s.CheckError = -1, s.LoadError
	case last.Ms < 0:
		s.Latency, s.CheckError = -1, last.Error
	default:
		s.Latency, s.CheckError = PingMedian(s.PingSamples), ""
	}
}

// PingMedian is the median of the answers among the samples, -1 without any.
func PingMedian(samples []models.PingSample) int {
	if len(samples) == 0 {
		return -1
	}
	since := samples[len(samples)-1].At.Add(-pingWindow)
	var answers []int
	for _, sample := range samples {
		if sample.Ms > 0 && !sample.At.Before(since) {
			answers = append(answers, sample.Ms)
		}
	}
	sort.Ints(answers)
	switch len(answers) {
	case 0:
		return -1
	case 2:
		return (answers[0] + answers[1] + 1) / 2
	default:
		return answers[len(answers)/2]
	}
}

// ServersCount says «1 сервер», «3 сервера», «134 сервера», «25 серверов».
func ServersCount(n int) string {
	word := "серверов"
	if tens, units := n%100, n%10; tens < 11 || tens > 14 {
		switch {
		case units == 1:
			word = "сервер"
		case units >= 2 && units <= 4:
			word = "сервера"
		}
	}
	return strconv.Itoa(n) + " " + word
}

// PingSilent reports a server whose two latest checks both got no answer.
func PingSilent(s models.Server) bool {
	n := len(s.PingSamples)
	return n >= 2 && s.PingSamples[n-1].Ms < 0 && s.PingSamples[n-2].Ms < 0
}
