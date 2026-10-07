package ratelimit

import (
	"testing"
	"time"
)

func TestLimiter(t *testing.T) {
	l := New()
	now := time.Unix(1000, 0)
	for i := 0; i < 3; i++ {
		if ok, _ := l.Allow("k", 3, now); !ok {
			t.Fatal("burst")
		}
	}
	ok, wait := l.Allow("k", 3, now)
	if ok || wait <= 0 || wait > 21*time.Second {
		t.Fatalf("4th: %v %v", ok, wait)
	}
	if ok, _ := l.Allow("other", 3, now); !ok {
		t.Fatal("keys are separate")
	}
	if ok, _ := l.Allow("k", 3, now.Add(20*time.Second)); !ok {
		t.Fatal("refilled after 20 s")
	}
	if ok, _ := l.Allow("k", 0, now); !ok {
		t.Fatal("0 = unlimited")
	}
}
