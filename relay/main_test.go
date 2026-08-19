package main

import (
	"testing"
	"time"
)

func TestEnvBackedDefaults(t *testing.T) {
	// Unset keys fall back to the provided default.
	if got := envInt("SYNCSWARM_TEST_UNSET_INT", 64512); got != 64512 {
		t.Fatalf("envInt default = %d, want 64512", got)
	}
	if got := envBool("SYNCSWARM_TEST_UNSET_BOOL", true); got != true {
		t.Fatalf("envBool default = %v, want true", got)
	}
	if got := envDur("SYNCSWARM_TEST_UNSET_DUR", time.Minute); got != time.Minute {
		t.Fatalf("envDur default = %v, want 1m", got)
	}

	// Set keys override, and bad values fall back to the default.
	t.Setenv("SYNCSWARM_TEST_INT", "42")
	if got := envInt("SYNCSWARM_TEST_INT", 0); got != 42 {
		t.Fatalf("envInt = %d, want 42", got)
	}
	t.Setenv("SYNCSWARM_TEST_INT_BAD", "notanumber")
	if got := envInt("SYNCSWARM_TEST_INT_BAD", 7); got != 7 {
		t.Fatalf("envInt(bad) = %d, want fallback 7", got)
	}
	t.Setenv("SYNCSWARM_TEST_BOOL", "false")
	if got := envBool("SYNCSWARM_TEST_BOOL", true); got != false {
		t.Fatalf("envBool = %v, want false", got)
	}
	t.Setenv("SYNCSWARM_TEST_DUR", "30m")
	if got := envDur("SYNCSWARM_TEST_DUR", 0); got != 30*time.Minute {
		t.Fatalf("envDur = %v, want 30m", got)
	}
}

func TestLocalizeAddr(t *testing.T) {
	cases := map[string]string{
		":8080":           "127.0.0.1:8080",
		"0.0.0.0:8080":    "0.0.0.0:8080",
		"relay.host:9000": "relay.host:9000",
		"127.0.0.1:8080":  "127.0.0.1:8080",
	}
	for in, want := range cases {
		if got := localizeAddr(in); got != want {
			t.Fatalf("localizeAddr(%q) = %q, want %q", in, got, want)
		}
	}
}
