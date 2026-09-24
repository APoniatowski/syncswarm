// Command relay runs a standalone SyncSwarm relay node: it forwards onion-wrapped
// traffic for other peers and (optionally) holds messages for offline recipients,
// so anyone can host one to strengthen the network. A relay only ever peels a
// single onion layer with its own node key to learn the next hop — it never holds
// the content key, so it cannot read the messages it carries.
//
// Configuration comes from flags, each defaulting to an environment variable so
// the same binary is convenient both on the command line and in a container.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/APoniatowski/syncswarm/swarmsync"
)

func main() {
	discPort := flag.Int("disc", envInt("SYNCSWARM_DISCOVERY_PORT", 64512), "UDP discovery port")
	dataPort := flag.Int("data", envInt("SYNCSWARM_DATA_PORT", 64513), "TCP data port")
	storageDir := flag.String("storage", envStr("SYNCSWARM_STORAGE_DIR", "./relay-data"), "storage directory (node identity + offline queue)")
	bootstrap := flag.String("boot", envStr("SYNCSWARM_BOOTSTRAP", ""), "comma-separated bootstrap peers (host:discPort)")
	bridgeListen := flag.String("bridge-listen", envStr("SYNCSWARM_BRIDGE_LISTEN", ""), "TCP address to accept inbound discovery bridges on (e.g. :64514); empty = off")
	bridgePSKFile := flag.String("bridge-psk-file", envStr("SYNCSWARM_BRIDGE_PSK_FILE", ""),
		"file containing a pre-shared key that gates who may attach a bridge (inbound and outbound); empty = open bridge")
	var bridge bridgeFlag
	bridge.setFrom(envStr("SYNCSWARM_BRIDGE", ""))
	flag.Var(&bridge, "bridge", "open outbound discovery bridges. Bare -bridge uses the default bridge hosts; -bridge=host:64514[,...] targets specific transport nodes")
	auto := flag.Bool("auto", envBool("SYNCSWARM_AUTO_INTERFACE", false), "zero-config LAN discovery via IPv6 link-local multicast (no bootstrap/DNS needed on the same network)")
	lora := flag.String("lora", envStr("SYNCSWARM_LORA_DEVICE", ""), "serial LoRa modem device to join the mesh over the air (e.g. /dev/ttyUSB0); empty = off")
	loraBaud := flag.Int("lora-baud", envInt("SYNCSWARM_LORA_BAUD", 0), "LoRa modem baud rate (0 = default)")
	serial := flag.String("serial", envStr("SYNCSWARM_SERIAL_DEVICE", ""), "KISS/serial radio modem device (e.g. /dev/ttyS0); empty = off")
	serialBaud := flag.Int("serial-baud", envInt("SYNCSWARM_SERIAL_BAUD", 0), "serial modem baud rate (0 = default)")
	loraDuty := flag.Float64("lora-duty", envFloat("SYNCSWARM_LORA_DUTY", 0), "LoRa transmit duty-cycle limit as a fraction of airtime per hour (e.g. 0.01 for the 1% licence-free bands allow; 0 = unlimited)")
	serialDuty := flag.Float64("serial-duty", envFloat("SYNCSWARM_SERIAL_DUTY", 0), "serial radio transmit duty-cycle limit, as -lora-duty")
	storeForward := flag.Bool("store", envBool("SYNCSWARM_STORE_FORWARD", true), "hold messages for offline recipients")
	storeTTL := flag.Duration("store-ttl", envDur("SYNCSWARM_STORE_FORWARD_TTL", 0), "how long to hold offline messages (0 = default)")
	scoring := flag.Bool("scoring", envBool("SYNCSWARM_RELAY_SCORING", true), "challenge peer relays and route around silent droppers")
	relayRole := flag.Bool("relay", envBool("SYNCSWARM_RELAY", true), "advertise this node as a relay that forwards for others. Automatically suspended while AutoNAT finds this node unreachable, since an undialable relay poisons other nodes' path selection")
	httpAddr := flag.String("http", envStr("SYNCSWARM_HTTP_ADDR", ""), "address for the health/metrics HTTP server (empty = disabled, e.g. :8080)")
	statsEvery := flag.Duration("stats", envDur("SYNCSWARM_STATS_INTERVAL", time.Minute), "how often to log a status line (0 = never)")
	healthcheck := flag.Bool("healthcheck", false, "probe the local HTTP health endpoint and exit (for container HEALTHCHECK)")
	flag.Parse()

	if *healthcheck {
		os.Exit(runHealthcheck(*httpAddr))
	}

	var peers []string
	if s := strings.TrimSpace(*bootstrap); s != "" {
		peers = strings.Split(s, ",")
	}
	// A bare -bridge means "bridge me somewhere sensible" and resolves to the
	// baked-in defaults; an explicit list wins. Absent flag = no bridge at all.
	bridges := bridge.resolve()

	// The bridge PSK is deliberately not a plain flag: a command line is visible to
	// every local user via ps, so a key passed that way would leak to anyone with a
	// shell on the host. Take it from the environment or a file instead.
	bridgePSK, err := loadBridgePSK(*bridgePSKFile)
	if err != nil {
		log.Fatalf("relay: bridge PSK: %v", err)
	}
	if len(bridgePSK) > 0 {
		log.Printf("relay: bridge access restricted by pre-shared key")
	}

	// A bool-style flag cannot take a space-separated value, so "-bridge host:port"
	// would silently parse as a bare -bridge plus a stray argument. Fail loudly
	// rather than quietly bridging somewhere the operator did not intend.
	if flag.NArg() > 0 {
		log.Fatalf("relay: unexpected argument %q — use -bridge=host:64514 (with '='), not a space", flag.Arg(0))
	}

	// The reachability callback needs the node, which does not exist until New
	// returns; an atomic handle keeps that race-free under the background
	// goroutine that fires it.
	var nodeRef atomic.Pointer[swarmsync.SyncSwarm]

	// Auto-demote: a relay that cannot accept inbound connections still advertises
	// the "relay" capability, so other nodes keep selecting it as an onion hop,
	// fail to dial it, waste paths and eventually excommunicate it. AutoNAT already
	// determines reachability; wire it to the advertisement so a misconfigured or
	// newly-NAT'd relay stops poisoning everyone's path selection by itself, and
	// resumes automatically when reachability returns.
	var onReachability func(bool)
	if *relayRole {
		onReachability = func(reachable bool) {
			n := nodeRef.Load()
			if n == nil {
				return
			}
			n.SetRelay(reachable)
			if reachable {
				log.Printf("relay: reachable from the outside — advertising relay capability")
			} else {
				log.Printf("relay: NOT reachable from the outside — suspending relay advertisement " +
					"(check port forwarding/firewall for the data port); will resume automatically if that changes")
			}
		}
	}

	node, err := swarmsync.New(swarmsync.Options{
		StorageDir:      *storageDir,
		Relay:           *relayRole,
		StoreForward:    *storeForward,
		StoreForwardTTL: *storeTTL,
		RelayScoring:    *scoring,
		BootstrapPeers:  peers,
		BridgePeers:     bridges,
		BridgeListen:    *bridgeListen,
		BridgePSK:       bridgePSK,
		AutoInterface:   *auto,
		LoRaDevice:      *lora,
		LoRaBaud:        *loraBaud,
		SerialDevice:    *serial,
		SerialBaud:      *serialBaud,
		LoRaDutyCycle:   *loraDuty,
		SerialDutyCycle: *serialDuty,
		// Detect reachability even without AutoRelay: a relay does not want
		// circuit reservations, only an honest answer about whether it is dialable.
		OnReachabilityChange: onReachability,
		DiscoveryPort:        *discPort,
		DataPort:             *dataPort,
		// No content Key and no erasure coding: a relay forwards opaque blobs and
		// never seals or opens application data.
	})
	if err != nil {
		log.Fatalf("relay: init failed: %v", err)
	}
	nodeRef.Store(node) // before Start, so the callback never sees a nil node
	if err := node.Start(); err != nil {
		log.Fatalf("relay: start failed: %v", err)
	}

	log.Printf("SyncSwarm relay online")
	log.Printf("  node id:        %s", node.NodeID())
	log.Printf("  discovery port: %d (UDP)", node.DiscoveryPort())
	log.Printf("  data port:      %d (TCP)", node.DataPort())
	log.Printf("  relay role:     %v   store-forward: %v   relay-scoring: %v", *relayRole, *storeForward, *scoring)
	if len(peers) > 0 {
		log.Printf("  bootstrap:      %s", strings.Join(peers, ", "))
	}
	log.Printf("  content key:    (none — a relay cannot read the traffic it carries)")

	started := time.Now()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if *httpAddr != "" {
		go serveHTTP(ctx, *httpAddr, node, started)
		log.Printf("  http:           %s (/healthz, /stats)", *httpAddr)
	}
	if *statsEvery > 0 {
		go logStats(ctx, node, *statsEvery)
	}

	<-ctx.Done()
	log.Printf("relay: shutting down…")
	if err := node.Stop(); err != nil {
		log.Printf("relay: stop error: %v", err)
	}
}

// statusSnapshot is the JSON returned by /stats.
type statusSnapshot struct {
	NodeID     string      `json:"node_id"`
	UptimeSec  int64       `json:"uptime_seconds"`
	Stats      interface{} `json:"stats"`
	PeerHealth interface{} `json:"peer_health"`
	// Peers lists exactly who this relay is talking to — the answer to "is the
	// peer I expect actually here", which aggregate counts cannot give.
	Peers interface{} `json:"peers"`
}

func snapshot(node *swarmsync.SyncSwarm, started time.Time) statusSnapshot {
	return statusSnapshot{
		NodeID:     node.NodeID(),
		UptimeSec:  int64(time.Since(started).Seconds()),
		Stats:      node.Stats(),
		PeerHealth: node.PeerHealth(),
		Peers:      node.Peers(),
	}
}

// logStats periodically logs a one-line health summary for the operator.
func logStats(ctx context.Context, node *swarmsync.SyncSwarm, every time.Duration) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s := node.Stats()
			h := node.PeerHealth()
			log.Printf("status: peers=%d (active=%d, subnets=%d) forwarded=%d received=%d stored=%d dropped=%d excommunicated=%d",
				h.Total, h.Active, h.Subnets,
				s.FragmentsForwarded, s.FragmentsReceived, s.OfflineStored, s.PacketsDropped, s.Excommunications)
		}
	}
}

// serveHTTP exposes a health check and a JSON metrics snapshot.
func serveHTTP(ctx context.Context, addr string, node *swarmsync.SyncSwarm, started time.Time) {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok\n"))
	})
	mux.HandleFunc("/stats", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(snapshot(node, started))
	})

	srv := &http.Server{Addr: addr, Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdownCtx)
	}()
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Printf("http server error: %v", err)
	}
}

// runHealthcheck probes the local /healthz endpoint; returns a process exit code.
func runHealthcheck(httpAddr string) int {
	if httpAddr == "" {
		log.Printf("healthcheck: no HTTP endpoint configured (set -http / SYNCSWARM_HTTP_ADDR)")
		return 1
	}
	url := "http://" + localizeAddr(httpAddr) + "/healthz"
	client := &http.Client{Timeout: 3 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return 1
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusOK {
		return 0
	}
	return 1
}

// localizeAddr turns a bind address like ":8080" into a dialable "127.0.0.1:8080".
func localizeAddr(addr string) string {
	if strings.HasPrefix(addr, ":") {
		return "127.0.0.1" + addr
	}
	return addr
}

// --- env-backed flag defaults ---

func envStr(key, def string) string {
	if v, ok := os.LookupEnv(key); ok {
		return v
	}
	return def
}

func envInt(key string, def int) int {
	if v, ok := os.LookupEnv(key); ok {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return def
}

func envFloat(key string, def float64) float64 {
	if v, ok := os.LookupEnv(key); ok {
		if f, err := strconv.ParseFloat(v, 64); err == nil {
			return f
		}
	}
	return def
}

func envBool(key string, def bool) bool {
	if v, ok := os.LookupEnv(key); ok {
		if b, err := strconv.ParseBool(v); err == nil {
			return b
		}
	}
	return def
}

func envDur(key string, def time.Duration) time.Duration {
	if v, ok := os.LookupEnv(key); ok {
		if d, err := time.ParseDuration(v); err == nil {
			return d
		}
	}
	return def
}

// bridgeFlag lets -bridge be given with or without a value. Bare -bridge (no
// value) resolves to swarmsync.DefaultBridges, so an operator who wants a bridge
// but has no particular transport node in mind gets a working one; -bridge=a,b
// targets specific hosts. Omitting the flag entirely leaves bridging off, because
// a bridge is a standing connection and should stay opt-in.
type bridgeFlag struct {
	set  bool
	vals []string
}

// setFrom seeds the flag from an environment variable (same syntax as the flag
// value; empty means unset).
func (b *bridgeFlag) setFrom(v string) {
	if strings.TrimSpace(v) != "" {
		_ = b.Set(v)
	}
}

func (b *bridgeFlag) String() string { return strings.Join(b.vals, ",") }

// IsBoolFlag lets the flag package accept a bare -bridge with no value.
func (b *bridgeFlag) IsBoolFlag() bool { return true }

func (b *bridgeFlag) Set(v string) error {
	b.set = true
	v = strings.TrimSpace(v)
	// A bare -bridge is delivered as "true" by the flag package.
	if v == "" || v == "true" {
		return nil
	}
	if v == "false" {
		b.set = false
		return nil
	}
	for _, p := range strings.Split(v, ",") {
		if p = strings.TrimSpace(p); p != "" {
			b.vals = append(b.vals, p)
		}
	}
	return nil
}

// resolve returns the bridge targets: nothing when the flag was absent, the
// explicit list when given, and the defaults for a bare -bridge.
func (b *bridgeFlag) resolve() []string {
	if !b.set {
		return nil
	}
	if len(b.vals) > 0 {
		return b.vals
	}
	return swarmsync.DefaultBridges
}

// loadBridgePSK reads the bridge pre-shared key from SYNCSWARM_BRIDGE_PSK, or from
// the file named by -bridge-psk-file (whose contents are trimmed of surrounding
// whitespace, so an editor's trailing newline does not change the key). Returns
// nil when neither is set, which leaves bridges open.
//
// There is deliberately no -bridge-psk flag: a process's command line is world
// readable via ps, so a key given that way leaks to every local user.
func loadBridgePSK(path string) ([]byte, error) {
	var psk []byte
	var src string
	switch {
	case os.Getenv("SYNCSWARM_BRIDGE_PSK") != "":
		psk, src = []byte(os.Getenv("SYNCSWARM_BRIDGE_PSK")), "SYNCSWARM_BRIDGE_PSK"
	case path != "":
		b, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", path, err)
		}
		psk, src = bytes.TrimSpace(b), path
	default:
		return nil, nil
	}

	if len(psk) == 0 {
		return nil, fmt.Errorf("%s is empty", src)
	}
	// A short key is brute-forceable offline from a single captured handshake, so
	// refuse one rather than provide the appearance of access control.
	if len(psk) < swarmsync.MinBridgePSKLen {
		return nil, fmt.Errorf("%s: key is %d bytes; use at least %d", src, len(psk), swarmsync.MinBridgePSKLen)
	}
	return psk, nil
}
