package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/APoniatowski/syncswarm/swarmsync"
)

// TestBridgeFlag covers the three shapes -bridge can take. The distinction that
// matters: an *absent* flag must never bridge, because a bridge is a standing
// connection and defaulting every node to one would make the default hosts
// permanent load-bearing infrastructure.
func TestBridgeFlag(t *testing.T) {
	t.Run("absent means no bridge", func(t *testing.T) {
		var b bridgeFlag
		if got := b.resolve(); got != nil {
			t.Fatalf("resolve() = %v, want nil when the flag was never set", got)
		}
	})

	t.Run("bare -bridge uses the defaults", func(t *testing.T) {
		var b bridgeFlag
		if err := b.Set("true"); err != nil { // how the flag package delivers a bare flag
			t.Fatal(err)
		}
		got := b.resolve()
		if len(got) == 0 {
			t.Fatal("bare -bridge resolved to nothing; expected the default bridge hosts")
		}
		if len(got) != len(swarmsync.DefaultBridges) || got[0] != swarmsync.DefaultBridges[0] {
			t.Fatalf("resolve() = %v, want %v", got, swarmsync.DefaultBridges)
		}
	})

	t.Run("explicit list wins", func(t *testing.T) {
		var b bridgeFlag
		if err := b.Set("a.example:64514, b.example:64514 "); err != nil {
			t.Fatal(err)
		}
		got := b.resolve()
		want := []string{"a.example:64514", "b.example:64514"}
		if len(got) != len(want) {
			t.Fatalf("resolve() = %v, want %v", got, want)
		}
		for i := range want {
			if got[i] != want[i] {
				t.Fatalf("resolve()[%d] = %q, want %q (whitespace should be trimmed)", i, got[i], want[i])
			}
		}
	})

	t.Run("-bridge=false disables", func(t *testing.T) {
		var b bridgeFlag
		if err := b.Set("false"); err != nil {
			t.Fatal(err)
		}
		if got := b.resolve(); got != nil {
			t.Fatalf("resolve() = %v, want nil for -bridge=false", got)
		}
	})

	t.Run("env seeding", func(t *testing.T) {
		var b bridgeFlag
		b.setFrom("  ") // blank env must not enable bridging
		if got := b.resolve(); got != nil {
			t.Fatalf("resolve() = %v, want nil for a blank env value", got)
		}
		var c bridgeFlag
		c.setFrom("x.example:64514")
		if got := c.resolve(); len(got) != 1 || got[0] != "x.example:64514" {
			t.Fatalf("resolve() = %v, want [x.example:64514]", got)
		}
	})
}

func TestLoadBridgePSK(t *testing.T) {
	dir := t.TempDir()
	write := func(name, content string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}

	t.Run("unset leaves bridges open", func(t *testing.T) {
		got, err := loadBridgePSK("")
		if err != nil || got != nil {
			t.Fatalf("got (%q, %v), want (nil, nil)", got, err)
		}
	})

	t.Run("file is read and trimmed", func(t *testing.T) {
		// An editor's trailing newline must not silently change the key, or two
		// hosts configured with the "same" key would fail to bridge.
		got, err := loadBridgePSK(write("k", "a-sufficiently-long-key\n"))
		if err != nil {
			t.Fatal(err)
		}
		if string(got) != "a-sufficiently-long-key" {
			t.Fatalf("got %q, want the trimmed key", got)
		}
	})

	t.Run("short key is refused", func(t *testing.T) {
		if _, err := loadBridgePSK(write("short", "tiny")); err == nil {
			t.Fatal("a 4-byte key was accepted; it is brute-forceable from one handshake")
		}
	})

	t.Run("empty file is refused", func(t *testing.T) {
		if _, err := loadBridgePSK(write("empty", "   \n")); err == nil {
			t.Fatal("an empty key file was accepted, silently leaving the bridge open")
		}
	})

	t.Run("environment wins and is validated", func(t *testing.T) {
		t.Setenv("SYNCSWARM_BRIDGE_PSK", "env-provided-key-long-enough")
		got, err := loadBridgePSK(write("k2", "file-provided-key-long-enough"))
		if err != nil {
			t.Fatal(err)
		}
		if string(got) != "env-provided-key-long-enough" {
			t.Fatalf("got %q, want the environment value to take precedence", got)
		}
		t.Setenv("SYNCSWARM_BRIDGE_PSK", "short")
		if _, err := loadBridgePSK(""); err == nil {
			t.Fatal("a short key from the environment bypassed the length check")
		}
	})
}
