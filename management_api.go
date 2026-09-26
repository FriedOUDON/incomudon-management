package main

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/csv"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

const (
	managementAPIVersionPrefix         = "/v1"
	managementAPIHealthPermission      = "health.read"
	managementAPIRevokePermission      = "service_admission.revoke"
	managementAPIEventDeliveryDisabled = "disabled"
	managementAPIEventDeliveryLive     = "live"
	managementAPIAuditRetrieval        = false
	managementAPIMinimumTLSVersion     = tls.VersionTLS13
)

var (
	managementAPIFingerprintPattern     = regexp.MustCompile(`^[0-9a-f]{64}$`)
	managementAPIDecimalPattern         = regexp.MustCompile(`^[0-9]+$`)
	managementAPIPermissionPattern      = regexp.MustCompile(`^[a-z][a-z0-9._-]{0,63}$`)
	managementAPIKnownGlobalPermissions = map[string]struct{}{
		managementAPIHealthPermission: {},
		managementAPIRevokePermission: {},
	}
)

type managementAPIConfig struct {
	listen                string
	certificateFile       string
	privateKeyFile        string
	clientCAFile          string
	servicesFile          string
	channelACLFile        string
	globalPermissionsFile string
	grantSigningKeyFile   string
	grantKeyID            string
	grantIssuer           string
	grantAudience         string
	grantTTLSeconds       string
	eventDelivery         string
	aclReloadInterval     string
}

func (c managementAPIConfig) enabled() bool {
	return strings.TrimSpace(c.listen) != ""
}

type managementAPIService struct {
	serviceID         string
	apiRole           string
	enabled           bool
	channels          map[uint32]struct{}
	admissions        map[managementAdmissionKey]managementAdmissionACL
	globalPermissions map[string]struct{}
}

type managementAdmissionKey struct {
	channelID uint32
	senderID  uint32
}

type managementAdmissionACL struct {
	role              string
	allowListen       bool
	allowTalk         bool
	allowInterrupt    bool
	interruptPriority uint8
	enabled           bool
}

type managementAPIAuthorizer struct {
	byFingerprint map[string]*managementAPIService
	byService     map[string]*managementAPIService
}

type managementAPI struct {
	state                 *managementState
	authorizerMu          sync.RWMutex
	authorizer            managementAPIAuthorizer
	servicesFile          string
	channelACLFile        string
	globalPermissionsFile string
	aclReloadInterval     time.Duration
	issuer                *serviceAdmissionGrantIssuer
	revoker               managementServiceAdmissionRevoker
	recordingJobs         *managementRecordingJobs
	liveEvents            *managementLiveEventHub
	eventDelivery         string
	tlsConfig             *tls.Config
	listen                string
}

type managementServiceAdmissionRevoker interface {
	revokeServiceAdmission(context.Context, managementServiceAdmissionRevocationRequest) (privateControlAck, string, error)
}

type managementCapabilities struct {
	EventDelivery  string `json:"event_delivery"`
	AuditRetrieval bool   `json:"audit_retrieval"`
}

type managementHealthResponse struct {
	Status       string                 `json:"status"`
	Capabilities managementCapabilities `json:"capabilities"`
}

type managementChannelSummary struct {
	ChannelID        uint32 `json:"channel_id"`
	ParticipantCount int    `json:"participant_count"`
}

type managementParticipant struct {
	SenderID uint32 `json:"sender_id"`
	State    string `json:"state"`
}

type managementChannelListResponse struct {
	Channels []managementChannelSummary `json:"channels"`
}

type managementParticipantListResponse struct {
	ChannelID    uint32                  `json:"channel_id"`
	Participants []managementParticipant `json:"participants"`
}

func newManagementAPI(config managementAPIConfig, state *managementState, revoker managementServiceAdmissionRevoker) (*managementAPI, error) {
	if !config.enabled() {
		return nil, nil
	}
	if state == nil {
		return nil, fmt.Errorf("Management API requires state")
	}
	for label, value := range map[string]string{
		"server certificate":         config.certificateFile,
		"server private key":         config.privateKeyFile,
		"client CA":                  config.clientCAFile,
		"management services CSV":    config.servicesFile,
		"management channel ACL CSV": config.channelACLFile,
		"global permissions CSV":     config.globalPermissionsFile,
	} {
		if strings.TrimSpace(value) == "" {
			return nil, fmt.Errorf("Management API %s is required when the listener is enabled", label)
		}
	}
	certificate, err := tls.LoadX509KeyPair(config.certificateFile, config.privateKeyFile)
	if err != nil {
		return nil, fmt.Errorf("load Management API server certificate: %w", err)
	}
	caData, err := os.ReadFile(config.clientCAFile)
	if err != nil {
		return nil, fmt.Errorf("read Management API client CA: %w", err)
	}
	clientCAs := x509.NewCertPool()
	if !clientCAs.AppendCertsFromPEM(caData) {
		return nil, fmt.Errorf("Management API client CA contains no certificates")
	}
	authorizer, err := loadManagementAPIAuthorizer(config.servicesFile, config.channelACLFile, config.globalPermissionsFile)
	if err != nil {
		return nil, err
	}
	issuer, err := loadServiceAdmissionGrantIssuer(config)
	if err != nil {
		return nil, err
	}
	eventDelivery := strings.TrimSpace(config.eventDelivery)
	if eventDelivery == "" {
		eventDelivery = managementAPIEventDeliveryDisabled
	}
	if eventDelivery != managementAPIEventDeliveryDisabled && eventDelivery != managementAPIEventDeliveryLive {
		return nil, fmt.Errorf("Management API event delivery must be %q or %q", managementAPIEventDeliveryDisabled, managementAPIEventDeliveryLive)
	}
	aclReloadInterval, err := parseManagementACLReloadInterval(config.aclReloadInterval)
	if err != nil {
		return nil, err
	}
	var liveEvents *managementLiveEventHub
	if eventDelivery == managementAPIEventDeliveryLive {
		liveEvents = newManagementLiveEventHub()
	}
	state.setLiveEvents(liveEvents)
	recordingJobs := newManagementRecordingJobs()
	state.setRecordingJobs(recordingJobs)
	return &managementAPI{
		state:                 state,
		authorizer:            authorizer,
		servicesFile:          config.servicesFile,
		channelACLFile:        config.channelACLFile,
		globalPermissionsFile: config.globalPermissionsFile,
		aclReloadInterval:     aclReloadInterval,
		issuer:                issuer,
		revoker:               revoker,
		recordingJobs:         recordingJobs,
		liveEvents:            liveEvents,
		eventDelivery:         eventDelivery,
		listen:                config.listen,
		tlsConfig: &tls.Config{
			MinVersion:   managementAPIMinimumTLSVersion,
			Certificates: []tls.Certificate{certificate},
			ClientAuth:   tls.RequireAndVerifyClientCert,
			ClientCAs:    clientCAs,
		},
	}, nil
}

func (a *managementAPI) httpServer() *http.Server {
	return &http.Server{
		Addr:              a.listen,
		Handler:           a,
		TLSConfig:         a.tlsConfig,
		ReadHeaderTimeout: 5 * time.Second,
	}
}

func loadManagementAPIAuthorizer(servicesFile, channelACLFile, globalPermissionsFile string) (managementAPIAuthorizer, error) {
	serviceRows, err := readManagementCSV(servicesFile, []string{"service_id", "certificate_sha256", "api_role", "enabled"})
	if err != nil {
		return managementAPIAuthorizer{}, fmt.Errorf("read management services ACL: %w", err)
	}
	byService := make(map[string]*managementAPIService, len(serviceRows))
	byFingerprint := make(map[string]*managementAPIService, len(serviceRows))
	for rowNumber, row := range serviceRows {
		serviceID, fingerprint, role := row[0], row[1], row[2]
		enabled, err := parseManagementBool(row[3], "management-services.csv enabled")
		if err != nil {
			return managementAPIAuthorizer{}, fmt.Errorf("management-services.csv row %d: %w", rowNumber+2, err)
		}
		if !validManagementServiceID(serviceID) {
			return managementAPIAuthorizer{}, fmt.Errorf("management-services.csv row %d: invalid service_id", rowNumber+2)
		}
		if !managementAPIFingerprintPattern.MatchString(fingerprint) {
			return managementAPIAuthorizer{}, fmt.Errorf("management-services.csv row %d: certificate_sha256 must be lowercase SHA-256 hex", rowNumber+2)
		}
		if !validManagementAPIRole(role) {
			return managementAPIAuthorizer{}, fmt.Errorf("management-services.csv row %d: invalid api_role", rowNumber+2)
		}
		if _, duplicate := byService[serviceID]; duplicate {
			return managementAPIAuthorizer{}, fmt.Errorf("management-services.csv row %d: duplicate service_id", rowNumber+2)
		}
		if _, duplicate := byFingerprint[fingerprint]; duplicate {
			return managementAPIAuthorizer{}, fmt.Errorf("management-services.csv row %d: duplicate certificate_sha256", rowNumber+2)
		}
		service := &managementAPIService{
			serviceID:         serviceID,
			apiRole:           role,
			enabled:           enabled,
			channels:          make(map[uint32]struct{}),
			admissions:        make(map[managementAdmissionKey]managementAdmissionACL),
			globalPermissions: make(map[string]struct{}),
		}
		byService[serviceID] = service
		byFingerprint[fingerprint] = service
	}

	aclRows, err := readManagementCSV(channelACLFile, []string{"service_id", "channel_id", "sender_id", "admission_role", "allow_listen", "allow_talk", "allow_interrupt", "interrupt_priority", "enabled"})
	if err != nil {
		return managementAPIAuthorizer{}, fmt.Errorf("read management channel ACL: %w", err)
	}
	seenACL := make(map[string]struct{}, len(aclRows))
	for rowNumber, row := range aclRows {
		service, found := byService[row[0]]
		if !found || !service.enabled {
			return managementAPIAuthorizer{}, fmt.Errorf("management-channel-acl.csv row %d: service_id is unknown or disabled", rowNumber+2)
		}
		channelID, err := parseManagementU32(row[1], "channel_id", false)
		if err != nil {
			return managementAPIAuthorizer{}, fmt.Errorf("management-channel-acl.csv row %d: %w", rowNumber+2, err)
		}
		senderID, err := parseManagementU32(row[2], "sender_id", true)
		if err != nil {
			return managementAPIAuthorizer{}, fmt.Errorf("management-channel-acl.csv row %d: %w", rowNumber+2, err)
		}
		if row[3] != "recorder" && row[3] != "observer" && row[3] != "automation" {
			return managementAPIAuthorizer{}, fmt.Errorf("management-channel-acl.csv row %d: invalid admission_role", rowNumber+2)
		}
		allowListen, err := parseManagementBool(row[4], "allow_listen")
		if err != nil {
			return managementAPIAuthorizer{}, fmt.Errorf("management-channel-acl.csv row %d: %w", rowNumber+2, err)
		}
		allowTalk, err := parseManagementBool(row[5], "allow_talk")
		if err != nil {
			return managementAPIAuthorizer{}, fmt.Errorf("management-channel-acl.csv row %d: %w", rowNumber+2, err)
		}
		allowInterrupt, err := parseManagementBool(row[6], "allow_interrupt")
		if err != nil {
			return managementAPIAuthorizer{}, fmt.Errorf("management-channel-acl.csv row %d: %w", rowNumber+2, err)
		}
		priority, err := parseManagementU32(row[7], "interrupt_priority", false)
		if err != nil || priority > 255 {
			if err == nil {
				err = fmt.Errorf("interrupt_priority must be in 0..255")
			}
			return managementAPIAuthorizer{}, fmt.Errorf("management-channel-acl.csv row %d: %w", rowNumber+2, err)
		}
		enabled, err := parseManagementBool(row[8], "enabled")
		if err != nil {
			return managementAPIAuthorizer{}, fmt.Errorf("management-channel-acl.csv row %d: %w", rowNumber+2, err)
		}
		if (row[3] == "recorder" || row[3] == "observer") && (!allowListen || allowTalk || allowInterrupt || priority != 0) {
			return managementAPIAuthorizer{}, fmt.Errorf("management-channel-acl.csv row %d: %s requires receive-only permissions", rowNumber+2, row[3])
		}
		if allowInterrupt && (!allowTalk || priority == 0) {
			return managementAPIAuthorizer{}, fmt.Errorf("management-channel-acl.csv row %d: interrupt requires talk and non-zero priority", rowNumber+2)
		}
		if !allowInterrupt && priority != 0 {
			return managementAPIAuthorizer{}, fmt.Errorf("management-channel-acl.csv row %d: interrupt_priority requires allow_interrupt", rowNumber+2)
		}
		tuple := fmt.Sprintf("%s/%d/%d", service.serviceID, channelID, senderID)
		if _, duplicate := seenACL[tuple]; duplicate {
			return managementAPIAuthorizer{}, fmt.Errorf("management-channel-acl.csv row %d: duplicate service_id/channel_id/sender_id", rowNumber+2)
		}
		seenACL[tuple] = struct{}{}
		if enabled {
			service.channels[channelID] = struct{}{}
			service.admissions[managementAdmissionKey{channelID: channelID, senderID: senderID}] = managementAdmissionACL{
				role:              row[3],
				allowListen:       allowListen,
				allowTalk:         allowTalk,
				allowInterrupt:    allowInterrupt,
				interruptPriority: uint8(priority),
				enabled:           true,
			}
		}
	}

	globalRows, err := readManagementCSV(globalPermissionsFile, []string{"service_id", "permission", "enabled"})
	if err != nil {
		return managementAPIAuthorizer{}, fmt.Errorf("read Management API global permissions: %w", err)
	}
	seenPermissions := make(map[string]struct{}, len(globalRows))
	for rowNumber, row := range globalRows {
		service, found := byService[row[0]]
		if !found || !service.enabled {
			return managementAPIAuthorizer{}, fmt.Errorf("management-global-permissions.csv row %d: service_id is unknown or disabled", rowNumber+2)
		}
		if !managementAPIPermissionPattern.MatchString(row[1]) {
			return managementAPIAuthorizer{}, fmt.Errorf("management-global-permissions.csv row %d: invalid permission", rowNumber+2)
		}
		if _, known := managementAPIKnownGlobalPermissions[row[1]]; !known {
			return managementAPIAuthorizer{}, fmt.Errorf("management-global-permissions.csv row %d: unsupported permission", rowNumber+2)
		}
		enabled, err := parseManagementBool(row[2], "enabled")
		if err != nil {
			return managementAPIAuthorizer{}, fmt.Errorf("management-global-permissions.csv row %d: %w", rowNumber+2, err)
		}
		key := service.serviceID + "\x00" + row[1]
		if _, duplicate := seenPermissions[key]; duplicate {
			return managementAPIAuthorizer{}, fmt.Errorf("management-global-permissions.csv row %d: duplicate service_id/permission", rowNumber+2)
		}
		seenPermissions[key] = struct{}{}
		if enabled {
			service.globalPermissions[row[1]] = struct{}{}
		}
	}
	return managementAPIAuthorizer{byFingerprint: byFingerprint, byService: byService}, nil
}

func readManagementCSV(filename string, expectedHeader []string) ([][]string, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	reader := csv.NewReader(file)
	reader.FieldsPerRecord = len(expectedHeader)
	header, err := reader.Read()
	if err != nil {
		return nil, err
	}
	if len(header) != len(expectedHeader) {
		return nil, fmt.Errorf("unexpected header")
	}
	for index, name := range expectedHeader {
		if header[index] != name {
			return nil, fmt.Errorf("unexpected header")
		}
	}
	var rows [][]string
	for {
		row, err := reader.Read()
		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return nil, err
		}
		rows = append(rows, row)
	}
	return rows, nil
}

func parseManagementBool(value, label string) (bool, error) {
	switch value {
	case "true":
		return true, nil
	case "false":
		return false, nil
	default:
		return false, fmt.Errorf("%s must be true or false", label)
	}
}

func parseManagementU32(value, label string, nonzero bool) (uint32, error) {
	if !managementAPIDecimalPattern.MatchString(value) {
		return 0, fmt.Errorf("%s must be decimal u32", label)
	}
	parsed, err := strconv.ParseUint(value, 10, 32)
	if err != nil {
		return 0, fmt.Errorf("%s must be decimal u32", label)
	}
	if nonzero && parsed == 0 {
		return 0, fmt.Errorf("%s must be non-zero", label)
	}
	return uint32(parsed), nil
}

func validManagementAPIRole(role string) bool {
	switch role {
	case "viewer", "recorder", "operator", "auditor", "admin":
		return true
	default:
		return false
	}
}

func (a managementAPIAuthorizer) serviceForRequest(request *http.Request) (*managementAPIService, bool) {
	if request.TLS == nil || len(request.TLS.PeerCertificates) == 0 {
		return nil, false
	}
	fingerprint := fmt.Sprintf("%x", sha256.Sum256(request.TLS.PeerCertificates[0].Raw))
	service, found := a.byFingerprint[fingerprint]
	return service, found && service.enabled
}

func (s *managementAPIService) canReadChannels() bool {
	return (s.apiRole == "viewer" || s.apiRole == "recorder" || s.apiRole == "operator") && len(s.channels) > 0
}

func (s *managementAPIService) canReadChannel(channelID uint32) bool {
	if !s.canReadChannels() {
		return false
	}
	_, found := s.channels[channelID]
	return found
}

func (s *managementAPIService) canReadEventChannel(channelID uint32) bool {
	if s == nil || (s.apiRole != "viewer" && s.apiRole != "recorder" && s.apiRole != "operator" && s.apiRole != "auditor") {
		return false
	}
	_, found := s.channels[channelID]
	return found
}

func (s *managementAPIService) canOpenEventStream() bool {
	if s == nil {
		return false
	}
	if s.hasGlobalPermission(managementAPIHealthPermission) {
		return true
	}
	if s.apiRole != "viewer" && s.apiRole != "recorder" && s.apiRole != "operator" && s.apiRole != "auditor" {
		return false
	}
	return len(s.channels) > 0
}

func (s *managementAPIService) canReceiveEvent(event managementEvent) bool {
	if event.ChannelID != nil {
		return s.canReadEventChannel(*event.ChannelID)
	}
	return event.Type == "relay_health_changed" && s.hasGlobalPermission(managementAPIHealthPermission)
}

func (s *managementAPIService) hasGlobalPermission(permission string) bool {
	_, found := s.globalPermissions[permission]
	return found
}

func (s *managementAPIService) admissionACL(channelID, senderID uint32) (managementAdmissionACL, bool) {
	if s == nil {
		return managementAdmissionACL{}, false
	}
	acl, found := s.admissions[managementAdmissionKey{channelID: channelID, senderID: senderID}]
	return acl, found && acl.enabled
}

func (a *managementAPI) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	service, ok := a.authenticate(writer, request)
	if !ok {
		return
	}
	switch request.URL.Path {
	case managementAPIVersionPrefix + "/health":
		if request.Method != http.MethodGet {
			writeManagementAPIMethodNotAllowed(writer, http.MethodGet)
			return
		}
		a.handleHealth(writer, service)
	case managementAPIVersionPrefix + "/channels":
		if request.Method != http.MethodGet {
			writeManagementAPIMethodNotAllowed(writer, http.MethodGet)
			return
		}
		a.handleChannels(writer, service)
	case managementAPIVersionPrefix + "/events":
		a.handleEvents(writer, request, service)
	case managementAPIVersionPrefix + "/service-admission-grants":
		a.handleServiceAdmissionGrant(writer, request, service)
	case managementAPIVersionPrefix + "/service-admission-revocations":
		a.handleServiceAdmissionRevocation(writer, request, service)
	case managementAPIVersionPrefix + "/recording-jobs":
		a.handleRecordingJobStart(writer, request, service)
	default:
		if jobID, matched := managementAPIRecordingJobIDFromStopPath(request.URL.Path); matched {
			a.handleRecordingJobStop(writer, request, service, jobID)
			return
		}
		channelID, matched := managementAPIChannelIDFromPath(request.URL.Path)
		if !matched {
			writeManagementAPIError(writer, http.StatusNotFound)
			return
		}
		if request.Method != http.MethodGet {
			writeManagementAPIMethodNotAllowed(writer, http.MethodGet)
			return
		}
		a.handleParticipants(writer, service, channelID)
	}
}

func managementAPIRecordingJobIDFromStopPath(path string) (string, bool) {
	const prefix = managementAPIVersionPrefix + "/recording-jobs/"
	const suffix = "/stop"
	if !strings.HasPrefix(path, prefix) || !strings.HasSuffix(path, suffix) {
		return "", false
	}
	jobID := strings.TrimSuffix(strings.TrimPrefix(path, prefix), suffix)
	if strings.Contains(jobID, "/") || utf8.RuneCountInString(jobID) == 0 || utf8.RuneCountInString(jobID) > 128 {
		return "", false
	}
	return jobID, true
}

func (a *managementAPI) authenticate(writer http.ResponseWriter, request *http.Request) (*managementAPIService, bool) {
	a.authorizerMu.RLock()
	service, found := a.authorizer.serviceForRequest(request)
	a.authorizerMu.RUnlock()
	if !found {
		writeManagementAPIError(writer, http.StatusForbidden)
		return nil, false
	}
	return service, true
}

func writeManagementAPIMethodNotAllowed(writer http.ResponseWriter, method string) {
	writer.Header().Set("Allow", method)
	writeManagementAPIError(writer, http.StatusMethodNotAllowed)
}

func (a *managementAPI) handleHealth(writer http.ResponseWriter, service *managementAPIService) {
	if !service.hasGlobalPermission(managementAPIHealthPermission) {
		writeManagementAPIError(writer, http.StatusForbidden)
		return
	}
	writeJSON(writer, http.StatusOK, managementHealthResponse{
		Status: a.state.managementAPIHealthStatus(),
		Capabilities: managementCapabilities{
			EventDelivery:  a.eventDeliveryMode(),
			AuditRetrieval: managementAPIAuditRetrieval,
		},
	})
}

func (a *managementAPI) eventDeliveryMode() string {
	if a == nil || a.eventDelivery == "" {
		return managementAPIEventDeliveryDisabled
	}
	return a.eventDelivery
}

func (a *managementAPI) handleChannels(writer http.ResponseWriter, service *managementAPIService) {
	if !service.canReadChannels() {
		writeManagementAPIError(writer, http.StatusForbidden)
		return
	}
	channels, ready := a.state.managementAPIChannelState()
	if !ready {
		writeManagementAPIError(writer, http.StatusServiceUnavailable)
		return
	}
	response := managementChannelListResponse{Channels: make([]managementChannelSummary, 0)}
	for channelID, participants := range channels {
		if service.canReadChannel(channelID) {
			response.Channels = append(response.Channels, managementChannelSummary{ChannelID: channelID, ParticipantCount: len(participants)})
		}
	}
	sort.Slice(response.Channels, func(left, right int) bool {
		return response.Channels[left].ChannelID < response.Channels[right].ChannelID
	})
	writeJSON(writer, http.StatusOK, response)
}

func (a *managementAPI) handleParticipants(writer http.ResponseWriter, service *managementAPIService, channelID uint32) {
	if !service.canReadChannel(channelID) {
		writeManagementAPIError(writer, http.StatusForbidden)
		return
	}
	channels, ready := a.state.managementAPIChannelState()
	if !ready {
		writeManagementAPIError(writer, http.StatusServiceUnavailable)
		return
	}
	participants := channels[channelID]
	response := managementParticipantListResponse{ChannelID: channelID, Participants: make([]managementParticipant, 0, len(participants))}
	for senderID, state := range participants {
		response.Participants = append(response.Participants, managementParticipant{SenderID: senderID, State: state})
	}
	sort.Slice(response.Participants, func(left, right int) bool {
		return response.Participants[left].SenderID < response.Participants[right].SenderID
	})
	writeJSON(writer, http.StatusOK, response)
}

func managementAPIChannelIDFromPath(path string) (uint32, bool) {
	const prefix = managementAPIVersionPrefix + "/channels/"
	const suffix = "/participants"
	if !strings.HasPrefix(path, prefix) || !strings.HasSuffix(path, suffix) {
		return 0, false
	}
	value := strings.TrimSuffix(strings.TrimPrefix(path, prefix), suffix)
	if value == "" || strings.Contains(value, "/") {
		return 0, false
	}
	channelID, err := parseManagementU32(value, "channel_id", false)
	return channelID, err == nil
}

func (s *managementState) managementAPIHealthStatus() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if !s.connected {
		return "unhealthy"
	}
	if s.snapshotAt.IsZero() {
		return "degraded"
	}
	return "healthy"
}

func (s *managementState) managementAPIChannelState() (map[uint32]map[uint32]string, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if !s.connected || s.snapshotAt.IsZero() {
		return nil, false
	}
	channels := make(map[uint32]map[uint32]string, len(s.channels))
	for channelID, participants := range s.channels {
		copyParticipants := make(map[uint32]string, len(participants))
		for senderID, state := range participants {
			copyParticipants[senderID] = state
		}
		channels[channelID] = copyParticipants
	}
	return channels, true
}

func writeManagementAPIError(writer http.ResponseWriter, status int) {
	writeJSON(writer, status, map[string]string{"error": http.StatusText(status)})
}
