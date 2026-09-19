package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"log"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"
)

type managementState struct {
	mu            sync.RWMutex
	relayID       string
	connected     bool
	connectedAt   time.Time
	lastEventAt   time.Time
	lastEventType string
}

func (s *managementState) markConnected(relayID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.relayID = relayID
	s.connected = true
	s.connectedAt = time.Now().UTC()
}

func (s *managementState) markDisconnected() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.connected = false
}

func (s *managementState) recordLifecycleEvent(event privateControlLifecycleEvent) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.lastEventAt = time.Now().UTC()
	s.lastEventType = event.EventType
}

func (s *managementState) snapshot() map[string]any {
	s.mu.RLock()
	defer s.mu.RUnlock()
	status := "disconnected"
	if s.connected {
		status = "connected"
	}
	snapshot := map[string]any{
		"status": status,
	}
	if s.relayID != "" {
		snapshot["relay_id"] = s.relayID
	}
	if !s.connectedAt.IsZero() {
		snapshot["connected_at"] = s.connectedAt.Format(time.RFC3339)
	}
	if !s.lastEventAt.IsZero() {
		snapshot["last_event_at"] = s.lastEventAt.Format(time.RFC3339)
		snapshot["last_event_type"] = s.lastEventType
	}
	return snapshot
}

func main() {
	config, httpListen := loadConfiguration()
	state := &managementState{}
	client, err := newPrivateControlClient(config, state)
	if err != nil {
		log.Fatalf("invalid Private Control Link configuration: %v", err)
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	go client.run(ctx)

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodGet {
			writer.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		writeJSON(writer, http.StatusOK, state.snapshot())
	})
	mux.HandleFunc("/readyz", func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodGet {
			writer.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		snapshot := state.snapshot()
		status := http.StatusServiceUnavailable
		if snapshot["status"] == "connected" {
			status = http.StatusOK
		}
		writeJSON(writer, status, snapshot)
	})
	httpServer := &http.Server{Addr: httpListen, Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	go func() {
		log.Printf("management health listener enabled at %s", httpListen)
		if err := httpServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Printf("management health listener failed: %v", err)
			cancel()
		}
	}()

	<-ctx.Done()
	shutdownContext, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer shutdownCancel()
	if err := httpServer.Shutdown(shutdownContext); err != nil {
		log.Printf("management health listener shutdown: %v", err)
	}
}

func loadConfiguration() (privateControlClientConfig, string) {
	relayAddress := flag.String("pcl-relay-address", os.Getenv("INCOMUDON_MANAGEMENT_PCL_RELAY_ADDRESS"), "Relay Private Control Link address")
	serverName := flag.String("pcl-server-name", os.Getenv("INCOMUDON_MANAGEMENT_PCL_SERVER_NAME"), "expected Relay TLS server name")
	serviceID := flag.String("pcl-service-id", os.Getenv("INCOMUDON_MANAGEMENT_PCL_SERVICE_ID"), "Management Service ID")
	certificateFile := flag.String("pcl-cert-file", os.Getenv("INCOMUDON_MANAGEMENT_PCL_CERT_FILE"), "Management Service client certificate PEM file")
	privateKeyFile := flag.String("pcl-key-file", os.Getenv("INCOMUDON_MANAGEMENT_PCL_KEY_FILE"), "Management Service client private key PEM file")
	relayCAFile := flag.String("pcl-relay-ca-file", os.Getenv("INCOMUDON_MANAGEMENT_PCL_RELAY_CA_FILE"), "trusted Relay CA PEM file")
	httpListen := flag.String("http-listen", valueOrDefault(os.Getenv("INCOMUDON_MANAGEMENT_HTTP_LISTEN"), ":8080"), "local management health listener")
	flag.Parse()
	return privateControlClientConfig{
		relayAddress:    *relayAddress,
		serverName:      *serverName,
		serviceID:       *serviceID,
		certificateFile: *certificateFile,
		privateKeyFile:  *privateKeyFile,
		relayCAFile:     *relayCAFile,
	}, *httpListen
}

func valueOrDefault(value string, fallback string) string {
	if value == "" {
		return fallback
	}
	return value
}

func writeJSON(writer http.ResponseWriter, status int, value any) {
	writer.Header().Set("Content-Type", "application/json")
	writer.WriteHeader(status)
	_ = json.NewEncoder(writer).Encode(value)
}
