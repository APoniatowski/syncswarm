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
	"context"
	"encoding/json"
	"flag"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/APoniatowski/syncswarm/swarmsync"
)

func main() {
	discPort := flag.Int("disc", envInt("SYNCSWARM_DISCOVERY_PORT", 64512), "UDP discovery port")
	dataPort := flag.Int("data", envInt("SYNCSWARM_DATA_PORT", 64513), "TCP data port")
	storageDir := flag.String("storage", envStr("SYNCSWARM_STORAGE_DIR", "./relay-data"), "storage directory (node identity + offline queue)")
	bootstrap := flag.String("boot", envStr("SYNCSWARM_BOOTSTRAP", ""), "comma-separated bootstrap peers (host:discPort)")
	storeForward := flag.Bool("store", envBool("SYNCSWARM_STORE_FORWARD", true), "hold messages for offline recipients")
	storeTTL := flag.Duration("store-ttl", envDur("SYNCSWARM_STORE_FORWARD_TTL", 0), "how long to hold offline messages (0 = default)")
	scoring := flag.Bool("scoring", envBool("SYNCSWARM_RELAY_SCORING", true), "challenge peer relays and route around silent droppers")
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

	node, err := swarmsync.New(swarmsync.Options{
		StorageDir:      *storageDir,
		Relay:           true, // the whole point: forward for others
		StoreForward:    *storeForward,
		StoreForwardTTL: *storeTTL,
		RelayScoring:    *scoring,
		BootstrapPeers:  peers,
		DiscoveryPort:   *discPort,
		DataPort:        *dataPort,
		// No content Key and no erasure coding: a relay forwards opaque blobs and
		// never seals or opens application data.
	})
	if err != nil {
		log.Fatalf("relay: init failed: %v", err)
	}
	if err := node.Start(); err != nil {
		log.Fatalf("relay: start failed: %v", err)
	}

	log.Printf("SyncSwarm relay online")
	log.Printf("  node id:        %s", node.NodeID())
	log.Printf("  discovery port: %d (UDP)", node.DiscoveryPort())
	log.Printf("  data port:      %d (TCP)", node.DataPort())
	log.Printf("  store-forward:  %v   relay-scoring: %v", *storeForward, *scoring)
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
}

func snapshot(node *swarmsync.SyncSwarm, started time.Time) statusSnapshot {
	return statusSnapshot{
		NodeID:     node.NodeID(),
		UptimeSec:  int64(time.Since(started).Seconds()),
		Stats:      node.Stats(),
		PeerHealth: node.PeerHealth(),
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
