package monitor

import (
	"reflect"
	"testing"
)

func TestOneMissedCheckIsNotAnOutage(t *testing.T) {
	if got := confirmedDown(nil, []string{"Claude"}); len(got) != 0 {
		t.Fatalf("one missed check must not report the route down: %v", got)
	}
	if got := confirmedDown([]string{"Claude", "ChatGPT"}, []string{"Claude", "Google"}); !reflect.DeepEqual(got, []string{"Claude"}) {
		t.Fatalf("only a route that failed twice in a row is down: %v", got)
	}
	if got := confirmedDown([]string{"Claude"}, nil); len(got) != 0 {
		t.Fatalf("a route that answered again is not down: %v", got)
	}
}
