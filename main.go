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
	channels      map[uint32]map[uint32]string
	snapshotAt    time.Time
}

func newManagementState() *managementState {
	return &managementState{channels: make(map[uint32]map[uint32]string)}
}

func (s *managementState) markConnected(relayID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.relayID = relayID
	s.connected = true
	s.connectedAt = time.Now().UTC()
	// A reconnect requires a fresh authoritative snapshot before state is served.
	s.channels = make(map[uint32]map[uint32]string)
	s.snapshotAt = time.Time{}
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
	if event.ChannelID == nil || event.SenderID == nil {
		return
	}
	if s.channels == nil {
		s.channels = make(map[uint32]map[uint32]string)
	}
	participants := s.channels[*event.ChannelID]
	if participants == nil {
		participants = make(map[uint32]string)
		s.channels[*event.ChannelID] = participants
	}
	switch event.EventType {
	case "participant_joined":
		participants[*event.SenderID] = "idle"
	case "participant_left":
		delete(participants, *event.SenderID)
		if len(participants) == 0 {
			delete(s.channels, *event.ChannelID)
		}
	case "talk_started":
		participants[*event.SenderID] = "talking"
	case "talk_ended":
		if _, found := participants[*event.SenderID]; found {
			participants[*event.SenderID] = "idle"
		}
	}
}

func (s *managementState) applyRelayStateSnapshot(channels []privateControlSnapshotChannel) {
	projection := make(map[uint32]map[uint32]string, len(channels))
	for _, channel := range channels {
		participants := projection[channel.ChannelID]
		if participants == nil {
			participants = make(map[uint32]string)
			projection[channel.ChannelID] = participants
		}
		for _, participant := range channel.Participants {
			participants[participant.SenderID] = participant.State
		}
	}
	s.mu.Lock()
	s.channels = projection
	s.snapshotAt = time.Now().UTC()
	s.mu.Unlock()
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
	if !s.snapshotAt.IsZero() {
		snapshot["state_snapshot_at"] = s.snapshotAt.Format(time.RFC3339)
		snapshot["channel_count"] = len(s.channels)
	}
	return snapshot
}

func main() {
	config, httpListen, apiConfig := loadConfiguration()
	state := newManagementState()
	client, err := newPrivateControlClient(config, state)
	if err != nil {
		log.Fatalf("invalid Private Control Link configuration: %v", err)
	}
	api, err := newManagementAPI(apiConfig, state)
	if err != nil {
		log.Fatalf("invalid Management API configuration: %v", err)
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
		if _, ready := state.managementAPIChannelState(); ready {
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

	var apiServer *http.Server
	if api != nil {
		apiServer = api.httpServer()
		go func() {
			log.Printf("Management API mTLS listener enabled at %s", apiServer.Addr)
			if err := apiServer.ListenAndServeTLS("", ""); err != nil && !errors.Is(err, http.ErrServerClosed) {
				log.Printf("Management API listener failed: %v", err)
				cancel()
			}
		}()
	}

	<-ctx.Done()
	shutdownContext, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer shutdownCancel()
	if apiServer != nil {
		if err := apiServer.Shutdown(shutdownContext); err != nil {
			log.Printf("Management API listener shutdown: %v", err)
		}
	}
	if err := httpServer.Shutdown(shutdownContext); err != nil {
		log.Printf("management health listener shutdown: %v", err)
	}
}

func loadConfiguration() (privateControlClientConfig, string, managementAPIConfig) {
	transport := flag.String("pcl-transport", os.Getenv("INCOMUDON_MANAGEMENT_PCL_TRANSPORT"), "Private Control Link transport: uds or mtls-tcp")
	relayAddress := flag.String("pcl-relay-address", os.Getenv("INCOMUDON_MANAGEMENT_PCL_RELAY_ADDRESS"), "Relay Private Control Link mTLS address")
	udsSocketPath := flag.String("pcl-uds-socket-path", os.Getenv("INCOMUDON_MANAGEMENT_PCL_UDS_SOCKET_PATH"), "Relay Private Control Link UDS absolute socket path")
	serverName := flag.String("pcl-server-name", os.Getenv("INCOMUDON_MANAGEMENT_PCL_SERVER_NAME"), "expected Relay TLS server name")
	serviceID := flag.String("pcl-service-id", os.Getenv("INCOMUDON_MANAGEMENT_PCL_SERVICE_ID"), "Management Service ID")
	certificateFile := flag.String("pcl-cert-file", os.Getenv("INCOMUDON_MANAGEMENT_PCL_CERT_FILE"), "Management Service mTLS client certificate PEM file")
	privateKeyFile := flag.String("pcl-key-file", os.Getenv("INCOMUDON_MANAGEMENT_PCL_KEY_FILE"), "Management Service mTLS client private key PEM file")
	relayCAFile := flag.String("pcl-relay-ca-file", os.Getenv("INCOMUDON_MANAGEMENT_PCL_RELAY_CA_FILE"), "trusted Relay mTLS CA PEM file")
	httpListen := flag.String("http-listen", valueOrDefault(os.Getenv("INCOMUDON_MANAGEMENT_HTTP_LISTEN"), ":8080"), "local management health listener")
	apiListen := flag.String("api-listen", os.Getenv("INCOMUDON_MANAGEMENT_API_LISTEN"), "Management API mTLS listener; empty disables the API")
	apiCertificateFile := flag.String("api-cert-file", os.Getenv("INCOMUDON_MANAGEMENT_API_CERT_FILE"), "Management API server certificate PEM file")
	apiPrivateKeyFile := flag.String("api-key-file", os.Getenv("INCOMUDON_MANAGEMENT_API_KEY_FILE"), "Management API server private key PEM file")
	apiClientCAFile := flag.String("api-client-ca-file", os.Getenv("INCOMUDON_MANAGEMENT_API_CLIENT_CA_FILE"), "trusted Management API client CA PEM file")
	apiServicesFile := flag.String("api-services-file", os.Getenv("INCOMUDON_MANAGEMENT_API_SERVICES_FILE"), "management-services.csv path")
	apiChannelACLFile := flag.String("api-channel-acl-file", os.Getenv("INCOMUDON_MANAGEMENT_API_CHANNEL_ACL_FILE"), "management-channel-acl.csv path")
	apiGlobalPermissionsFile := flag.String("api-global-permissions-file", os.Getenv("INCOMUDON_MANAGEMENT_API_GLOBAL_PERMISSIONS_FILE"), "management-global-permissions.csv path")
	flag.Parse()
	return privateControlClientConfig{
			transport:       *transport,
			relayAddress:    *relayAddress,
			udsSocketPath:   *udsSocketPath,
			serverName:      *serverName,
			serviceID:       *serviceID,
			certificateFile: *certificateFile,
			privateKeyFile:  *privateKeyFile,
			relayCAFile:     *relayCAFile,
		}, *httpListen, managementAPIConfig{
			listen:                *apiListen,
			certificateFile:       *apiCertificateFile,
			privateKeyFile:        *apiPrivateKeyFile,
			clientCAFile:          *apiClientCAFile,
			servicesFile:          *apiServicesFile,
			channelACLFile:        *apiChannelACLFile,
			globalPermissionsFile: *apiGlobalPermissionsFile,
		}
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
