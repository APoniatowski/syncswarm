package iface

import (
	"errors"
	"sync"
	"time"
)

// ErrDutyCycleExceeded is returned by Send when transmitting the frame would push
// the interface past its configured transmit duty cycle. It is a back-pressure
// signal, not a fault: the caller should back off and retry later (discovery
// broadcasts are best-effort, so a skipped announce is simply re-sent next tick).
var ErrDutyCycleExceeded = errors.New("iface: transmit duty cycle exceeded")

// defaultDutyWindow is the averaging window for duty-cycle accounting. Licence-free
// sub-GHz bands are specified per hour (e.g. EU 868 MHz commonly allows 1% per
// hour), so that is the natural default.
const defaultDutyWindow = time.Hour

// dutyLimiter bounds how much of the wall clock an interface may spend
// transmitting, over a sliding window. Radio regulations in licence-free bands cap
// this (EU 868 MHz: typically 1%), and exceeding it is both illegal and antisocial
// on a shared channel — a mesh node that ignores it drowns out its neighbours.
//
// Airtime is estimated from the medium's bitrate, which is the best a
// framing-level limiter can do without modem telemetry; it is deliberately
// conservative (it counts the fully-escaped on-wire frame).
type dutyLimiter struct {
	mu       sync.Mutex
	window   time.Duration
	fraction float64 // e.g. 0.01 for 1%
	bitrate  int     // bits/sec, used to estimate airtime
	events   []dutyEvent
	spent    time.Duration
}

type dutyEvent struct {
	at  time.Time
	air time.Duration
}

// newDutyLimiter returns a limiter allowing `fraction` of `window` on air. A
// non-positive fraction or bitrate disables limiting (nil-safe: a nil *dutyLimiter
// allows everything).
func newDutyLimiter(fraction float64, bitrate int, window time.Duration) *dutyLimiter {
	if fraction <= 0 || bitrate <= 0 {
		return nil
	}
	if window <= 0 {
		window = defaultDutyWindow
	}
	return &dutyLimiter{window: window, fraction: fraction, bitrate: bitrate}
}

// airtime estimates how long n bytes occupy the channel at the medium's bitrate.
func (d *dutyLimiter) airtime(n int) time.Duration {
	return time.Duration(float64(n*8) / float64(d.bitrate) * float64(time.Second))
}

// budget is the total airtime permitted within one window.
func (d *dutyLimiter) budget() time.Duration {
	return time.Duration(float64(d.window) * d.fraction)
}

// allow reports whether an n-byte frame may be transmitted now, recording it
// against the budget when it may. A nil limiter always allows.
func (d *dutyLimiter) allow(n int) bool {
	if d == nil {
		return true
	}
	d.mu.Lock()
	defer d.mu.Unlock()

	now := time.Now()
	d.pruneLocked(now)

	air := d.airtime(n)
	if d.spent+air > d.budget() {
		return false
	}
	d.events = append(d.events, dutyEvent{at: now, air: air})
	d.spent += air
	return true
}

// pruneLocked drops events that have aged out of the sliding window.
func (d *dutyLimiter) pruneLocked(now time.Time) {
	cut := now.Add(-d.window)
	i := 0
	for ; i < len(d.events); i++ {
		if d.events[i].at.After(cut) {
			break
		}
		d.spent -= d.events[i].air
	}
	if i > 0 {
		d.events = append(d.events[:0], d.events[i:]...)
	}
	if d.spent < 0 {
		d.spent = 0
	}
}
