// Package ratelimit is a keyed token bucket (requests per minute).
package ratelimit

import (
	"sync"
	"time"
)

type bucket struct {
	tokens float64
	at     time.Time
}

// Limiter limits each key to perMin requests a minute, with bursts up to
// perMin.
type Limiter struct {
	mu   sync.Mutex
	b    map[string]*bucket
	last time.Time
}

// New makes a limiter.
func New() *Limiter { return &Limiter{b: map[string]*bucket{}} }

// Allow takes one token from key's bucket (perMin <= 0: unlimited). When
// refused it says how long until a token is back.
func (l *Limiter) Allow(key string, perMin int, now time.Time) (bool, time.Duration) {
	if perMin <= 0 {
		return true, 0
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if now.Sub(l.last) > time.Minute && len(l.b) > 10000 {
		for k, b := range l.b {
			if now.Sub(b.at) > 2*time.Minute {
				delete(l.b, k)
			}
		}
		l.last = now
	}
	rate := float64(perMin) / 60
	b, ok := l.b[key]
	if !ok {
		b = &bucket{tokens: float64(perMin), at: now}
		l.b[key] = b
	}
	b.tokens += now.Sub(b.at).Seconds() * rate
	if b.tokens > float64(perMin) {
		b.tokens = float64(perMin)
	}
	b.at = now
	if b.tokens >= 1 {
		b.tokens--
		return true, 0
	}
	return false, time.Duration((1 - b.tokens) / rate * float64(time.Second))
}
