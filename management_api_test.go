package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestManagementAPIMTLSAuthorizationAndChannelFiltering(t *testing.T) {
	caCertificate, caKey, roots := newManagementAPITestCA(t)
	serverCertificate, _, _ := newPrivateControlTestLeaf(t, caCertificate, caKey, 10, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, []string{"management.test"})
	viewerCertificate, viewerPEM, _ := newPrivateControlTestLeaf(t, caCertificate, caKey, 11, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, nil)
	healthCertificate, healthPEM, _ := newPrivateControlTestLeaf(t, caCertificate, caKey, 12, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, nil)
	unmappedCertificate, _, _ := newPrivateControlTestLeaf(t, caCertificate, caKey, 13, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, nil)

	viewer := &managementAPIService{
		serviceID:         "viewer-service",
		apiRole:           "viewer",
		enabled:           true,
		channels:          map[uint32]struct{}{100: {}},
		globalPermissions: map[string]struct{}{},
	}
	health := &managementAPIService{
		serviceID:         "health-service",
		apiRole:           "auditor",
		enabled:           true,
		channels:          map[uint32]struct{}{},
		globalPermissions: map[string]struct{}{managementAPIHealthPermission: {}},
	}
	state := newManagementState()
	state.markConnected("relay-test")
	state.applyRelayStateSnapshot([]privateControlSnapshotChannel{
		{ChannelID: 100, Participants: []privateControlSnapshotParticipant{{SenderID: 1, State: "idle"}}},
		{ChannelID: 200, Participants: []privateControlSnapshotParticipant{{SenderID: 2, State: "talking"}}},
	})
	api := &managementAPI{
		state: state,
		authorizer: managementAPIAuthorizer{byFingerprint: map[string]*managementAPIService{
			managementAPITestFingerprint(t, viewerPEM): viewer,
			managementAPITestFingerprint(t, healthPEM): health,
		}},
		tlsConfig: &tls.Config{
			MinVersion:   tls.VersionTLS13,
			Certificates: []tls.Certificate{serverCertificate},
			ClientAuth:   tls.RequireAndVerifyClientCert,
			ClientCAs:    roots,
		},
	}
	server := httptest.NewUnstartedServer(api)
	server.TLS = api.tlsConfig
	server.StartTLS()
	t.Cleanup(server.Close)

	viewerClient := newManagementAPITestClient(roots, viewerCertificate)
	healthClient := newManagementAPITestClient(roots, healthCertificate)
	unmappedClient := newManagementAPITestClient(roots, unmappedCertificate)

	response := managementAPITestGet(t, viewerClient, server.URL+"/v1/channels")
	if response.StatusCode != http.StatusOK {
		t.Fatalf("viewer channels status = %d", response.StatusCode)
	}
	var channels managementChannelListResponse
	decodeManagementAPITestJSON(t, response, &channels)
	if len(channels.Channels) != 1 || channels.Channels[0] != (managementChannelSummary{ChannelID: 100, ParticipantCount: 1}) {
		t.Fatalf("viewer channel response = %#v", channels)
	}

	response = managementAPITestGet(t, viewerClient, server.URL+"/v1/channels/100/participants")
	if response.StatusCode != http.StatusOK {
		t.Fatalf("viewer participants status = %d", response.StatusCode)
	}
	var participants managementParticipantListResponse
	decodeManagementAPITestJSON(t, response, &participants)
	if participants.ChannelID != 100 || len(participants.Participants) != 1 || participants.Participants[0] != (managementParticipant{SenderID: 1, State: "idle"}) {
		t.Fatalf("viewer participant response = %#v", participants)
	}

	if response = managementAPITestGet(t, viewerClient, server.URL+"/v1/channels/200/participants"); response.StatusCode != http.StatusForbidden {
		response.Body.Close()
		t.Fatalf("viewer unauthorized channel status = %d", response.StatusCode)
	}
	response.Body.Close()
	if response = managementAPITestGet(t, viewerClient, server.URL+"/v1/health"); response.StatusCode != http.StatusForbidden {
		response.Body.Close()
		t.Fatalf("viewer health status = %d", response.StatusCode)
	}
	response.Body.Close()

	response = managementAPITestGet(t, healthClient, server.URL+"/v1/health")
	if response.StatusCode != http.StatusOK {
		t.Fatalf("health-reader status = %d", response.StatusCode)
	}
	var healthResponse managementHealthResponse
	decodeManagementAPITestJSON(t, response, &healthResponse)
	if healthResponse.Status != "healthy" || healthResponse.Capabilities.EventDelivery != "disabled" || healthResponse.Capabilities.AuditRetrieval {
		t.Fatalf("health response = %#v", healthResponse)
	}
	if response = managementAPITestGet(t, healthClient, server.URL+"/v1/channels"); response.StatusCode != http.StatusForbidden {
		response.Body.Close()
		t.Fatalf("health-reader channels status = %d", response.StatusCode)
	}
	response.Body.Close()

	if response = managementAPITestGet(t, unmappedClient, server.URL+"/v1/channels"); response.StatusCode != http.StatusForbidden {
		response.Body.Close()
		t.Fatalf("unmapped certificate status = %d", response.StatusCode)
	}
	response.Body.Close()
}

func TestManagementAPILoadsCanonicalCSVs(t *testing.T) {
	directory := t.TempDir()
	servicesFile := filepath.Join(directory, "management-services.csv")
	aclFile := filepath.Join(directory, "management-channel-acl.csv")
	permissionsFile := filepath.Join(directory, "management-global-permissions.csv")
	if err := os.WriteFile(servicesFile, []byte("service_id,certificate_sha256,api_role,enabled\nviewer-service,aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa,viewer,true\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(aclFile, []byte("service_id,channel_id,sender_id,admission_role,allow_listen,allow_talk,allow_interrupt,interrupt_priority,enabled\nviewer-service,100,1,observer,true,false,false,0,true\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(permissionsFile, []byte("service_id,permission,enabled\nviewer-service,health.read,true\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	authorizer, err := loadManagementAPIAuthorizer(servicesFile, aclFile, permissionsFile)
	if err != nil {
		t.Fatal(err)
	}
	service := authorizer.byFingerprint["aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"]
	if service == nil || !service.canReadChannel(100) || !service.hasGlobalPermission("health.read") {
		t.Fatalf("loaded service = %#v", service)
	}
}

func newManagementAPITestCA(t *testing.T) (*x509.Certificate, *ecdsa.PrivateKey, *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(100),
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})) {
		t.Fatal("append Management API test CA")
	}
	return certificate, key, roots
}

func managementAPITestFingerprint(t *testing.T, certificatePEM []byte) string {
	t.Helper()
	block, _ := pem.Decode(certificatePEM)
	if block == nil {
		t.Fatal("decode certificate PEM")
	}
	certificate, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return fmt.Sprintf("%x", sha256.Sum256(certificate.Raw))
}

func newManagementAPITestClient(roots *x509.CertPool, certificate tls.Certificate) *http.Client {
	return &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{
		MinVersion:   tls.VersionTLS13,
		RootCAs:      roots,
		ServerName:   "management.test",
		Certificates: []tls.Certificate{certificate},
	}}}
}

func managementAPITestGet(t *testing.T, client *http.Client, url string) *http.Response {
	t.Helper()
	response, err := client.Get(url)
	if err != nil {
		t.Fatal(err)
	}
	return response
}

func decodeManagementAPITestJSON(t *testing.T, response *http.Response, target any) {
	t.Helper()
	defer response.Body.Close()
	if err := json.NewDecoder(response.Body).Decode(target); err != nil {
		t.Fatal(err)
	}
}

func TestManagementAPIRejectsStaleRelayState(t *testing.T) {
	state := newManagementState()
	state.applyRelayStateSnapshot([]privateControlSnapshotChannel{{ChannelID: 100, Participants: []privateControlSnapshotParticipant{}}})
	if _, ready := state.managementAPIChannelState(); ready {
		t.Fatal("state snapshot without a connected Relay was treated as current")
	}
	if status := state.managementAPIHealthStatus(); status != "unhealthy" {
		t.Fatalf("disconnected health status = %q", status)
	}
	state.markConnected("relay-test")
	if _, ready := state.managementAPIChannelState(); ready {
		t.Fatal("state from before the connection was treated as current")
	}
	if status := state.managementAPIHealthStatus(); status != "degraded" {
		t.Fatalf("connected state without a snapshot = %q", status)
	}
	state.applyRelayStateSnapshot([]privateControlSnapshotChannel{{ChannelID: 100, Participants: []privateControlSnapshotParticipant{}}})
	if _, ready := state.managementAPIChannelState(); !ready {
		t.Fatal("fresh connected Relay snapshot was not current")
	}
	state.markDisconnected()
	if _, ready := state.managementAPIChannelState(); ready {
		t.Fatal("disconnected Relay state remained current")
	}
	state.markConnected("relay-test")
	if _, ready := state.managementAPIChannelState(); ready {
		t.Fatal("reconnected Relay served the previous snapshot")
	}
}

func TestManagementAPIChannelPathValidation(t *testing.T) {
	for path, want := range map[string]struct {
		channelID uint32
		matched   bool
	}{
		"/v1/channels/100/participants":  {100, true},
		"/v1/channels/0/participants":    {0, true},
		"/v1/channels/-1/participants":   {0, false},
		"/v1/channels/100":               {0, false},
		"/v1/channels/100/participants/": {0, false},
	} {
		gotID, gotMatch := managementAPIChannelIDFromPath(path)
		if gotID != want.channelID || gotMatch != want.matched {
			t.Fatalf("path %q = (%d, %v), want (%d, %v)", path, gotID, gotMatch, want.channelID, want.matched)
		}
	}
}

func TestManagementAPICSVRejectsUnknownGlobalPermission(t *testing.T) {
	directory := t.TempDir()
	servicesFile := filepath.Join(directory, "management-services.csv")
	aclFile := filepath.Join(directory, "management-channel-acl.csv")
	permissionsFile := filepath.Join(directory, "management-global-permissions.csv")
	if err := os.WriteFile(servicesFile, []byte("service_id,certificate_sha256,api_role,enabled\nviewer-service,aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa,viewer,true\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(aclFile, []byte("service_id,channel_id,sender_id,admission_role,allow_listen,allow_talk,allow_interrupt,interrupt_priority,enabled\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(permissionsFile, []byte("service_id,permission,enabled\nviewer-service,unknown.permission,true\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := loadManagementAPIAuthorizer(servicesFile, aclFile, permissionsFile)
	if err == nil || !strings.Contains(err.Error(), "unsupported permission") {
		t.Fatalf("unexpected CSV result: %v", err)
	}
}

func TestManagementAPICSVRejectsNonCanonicalBoolean(t *testing.T) {
	directory := t.TempDir()
	servicesFile := filepath.Join(directory, "management-services.csv")
	aclFile := filepath.Join(directory, "management-channel-acl.csv")
	permissionsFile := filepath.Join(directory, "management-global-permissions.csv")
	if err := os.WriteFile(servicesFile, []byte("service_id,certificate_sha256,api_role,enabled\nviewer-service,aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa,viewer,TRUE\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(aclFile, []byte("service_id,channel_id,sender_id,admission_role,allow_listen,allow_talk,allow_interrupt,interrupt_priority,enabled\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(permissionsFile, []byte("service_id,permission,enabled\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := loadManagementAPIAuthorizer(servicesFile, aclFile, permissionsFile)
	if err == nil || !strings.Contains(err.Error(), "enabled must be true or false") {
		t.Fatalf("unexpected CSV result: %v", err)
	}
}
