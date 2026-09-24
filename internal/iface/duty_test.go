package iface

import (
	"net"
	"testing"
	"time"
)

func TestDutyLimiter_Disabled(t *testing.T) {
	// A nil limiter (fraction or bitrate <= 0) never blocks.
	if newDutyLimiter(0, 5000, time.Hour) != nil {
		t.Fatal("zero fraction should disable limiting")
	}
	if newDutyLimiter(0.01, 0, time.Hour) != nil {
		t.Fatal("zero bitrate should disable limiting")
	}
	var nilLimiter *dutyLimiter
	if !nilLimiter.allow(1000) {
		t.Fatal("a nil limiter must allow everything")
	}
}

func TestDutyLimiter_EnforcesBudget(t *testing.T) {
	// 1% of a 1-second window at 1000 bits/sec = 10ms of airtime = 1.25 bytes...
	// use a friendlier setup: 10% of 1s at 8000 bits/sec = 100ms = 100 bytes.
	d := newDutyLimiter(0.10, 8000, time.Second)
	if d == nil {
		t.Fatal("limiter should be enabled")
	}
	if got := d.budget(); got != 100*time.Millisecond {
		t.Fatalf("budget = %v, want 100ms", got)
	}
	if got := d.airtime(100); got != 100*time.Millisecond {
		t.Fatalf("airtime(100B) = %v, want 100ms", got)
	}

	if !d.allow(50) {
		t.Fatal("first 50 bytes should fit the budget")
	}
	if !d.allow(50) {
		t.Fatal("second 50 bytes should exactly fill the budget")
	}
	if d.allow(1) {
		t.Fatal("a further byte exceeds the duty cycle and must be refused")
	}
}

func TestDutyLimiter_RecoversAfterWindow(t *testing.T) {
	d := newDutyLimiter(0.10, 8000, 100*time.Millisecond) // budget = 10ms = 10 bytes
	if !d.allow(10) {
		t.Fatal("initial send should fit")
	}
	if d.allow(1) {
		t.Fatal("budget should be exhausted")
	}
	time.Sleep(150 * time.Millisecond) // let the window slide past the first send
	if !d.allow(10) {
		t.Fatal("budget should recover once the window has passed")
	}
}

// TestKISS_DutyCycleRefusesOverBudget checks the limiter is actually enforced by
// the radio interface's Send, surfacing ErrDutyCycleExceeded rather than
// transmitting over budget.
func TestKISS_DutyCycleRefusesOverBudget(t *testing.T) {
	mine, peer := net.Pipe()
	defer peer.Close()
	k := newKISSInterface("lora", mine, KindLoRa,
		Caps{MTU: 500, Bitrate: 8000, Broadcast: true})
	defer k.Close()
	k.SetDutyCycle(0.10, time.Second) // 100ms budget => ~100 bytes of airtime

	go func() { // drain whatever does get transmitted
		buf := make([]byte, 4096)
		for {
			if _, err := peer.Read(buf); err != nil {
				return
			}
		}
	}()

	if err := k.Send(Broadcast, make([]byte, 80)); err != nil {
		t.Fatalf("first frame should be within budget: %v", err)
	}
	// The next frame pushes past the 100-byte airtime budget.
	if err := k.Send(Broadcast, make([]byte, 80)); err != ErrDutyCycleExceeded {
		t.Fatalf("over-budget send = %v, want ErrDutyCycleExceeded", err)
	}
}
