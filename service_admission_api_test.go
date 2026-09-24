package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestServiceAdmissionGrantIssuerProducesRelayCompatibleJWS(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	issuer := &serviceAdmissionGrantIssuer{
		privateKey: privateKey,
		keyID:      "management-ed25519-test",
		issuer:     "https://management.test",
		audience:   "relay-test",
		lifetime:   5 * time.Minute,
		issued:     make(map[string]issuedServiceAdmissionGrant),
	}
	workerKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_700_000_000, 0).UTC()
	grant, expiresAt, err := issuer.issue("recorder-01", managementAdmissionACL{
		role: "recorder", allowListen: true, enabled: true,
	}, managementServiceAdmissionGrantRequest{
		ChannelID:        100,
		SenderID:         9001,
		Role:             "recorder",
		ServicePublicKey: base64.RawURLEncoding.EncodeToString(workerKey),
	}, now)
	if err != nil {
		t.Fatal(err)
	}
	if !expiresAt.Equal(now.Add(5*time.Minute)) || len(grant) > serviceAdmissionGrantMaximumBytes {
		t.Fatalf("grant expiry/size = %s/%d", expiresAt, len(grant))
	}
	segments := strings.Split(grant, ".")
	if len(segments) != 3 {
		t.Fatalf("compact JWS segments = %d", len(segments))
	}
	signature, err := base64.RawURLEncoding.DecodeString(segments[2])
	if err != nil || !ed25519.Verify(publicKey, []byte(segments[0]+"."+segments[1]), signature) {
		t.Fatal("grant signature is not Relay-verifiable")
	}
	headerBytes, err := base64.RawURLEncoding.DecodeString(segments[0])
	if err != nil {
		t.Fatal(err)
	}
	var header serviceAdmissionGrantHeader
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		t.Fatal(err)
	}
	if header != (serviceAdmissionGrantHeader{Algorithm: "EdDSA", KeyID: "management-ed25519-test", Type: "incomudon-service-admission+jwt"}) {
		t.Fatalf("grant header = %#v", header)
	}
	payload, err := base64.RawURLEncoding.DecodeString(segments[1])
	if err != nil {
		t.Fatal(err)
	}
	var claims serviceAdmissionGrantClaims
	if err := json.Unmarshal(payload, &claims); err != nil {
		t.Fatal(err)
	}
	thumbprint := sha256.Sum256(workerKey)
	if claims.Issuer != "https://management.test" || claims.Audience != "relay-test" || claims.ServiceID != "recorder-01" ||
		claims.ChannelID != 100 || claims.SenderID != 9001 || claims.Role != "recorder" || claims.Permissions != 1 ||
		claims.Priority != nil || claims.Confirmation.JWKThumbprint != base64.RawURLEncoding.EncodeToString(thumbprint[:]) {
		t.Fatalf("grant claims = %#v", claims)
	}
	grantIDHash := sha256.Sum256([]byte(claims.GrantID))
	if _, found := issuer.issuedGrant(base64.RawURLEncoding.EncodeToString(grantIDHash[:]), now); !found {
		t.Fatal("issued grant was not retained for bounded grant-specific revocation")
	}
}

func TestManagementAPIServiceAdmissionGrantIsACLBound(t *testing.T) {
	issuer := newTestServiceAdmissionGrantIssuer(t)
	api := &managementAPI{issuer: issuer}
	service := &managementAPIService{
		serviceID: "automation-01",
		apiRole:   "operator",
		admissions: map[managementAdmissionKey]managementAdmissionACL{
			{channelID: 100, senderID: 9001}: {
				role: "automation", allowListen: true, allowTalk: true, allowInterrupt: true, interruptPriority: 200, enabled: true,
			},
		},
	}
	workerKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	body, err := json.Marshal(managementServiceAdmissionGrantRequest{
		ChannelID: 100, SenderID: 9001, Role: "automation", RequestTalk: true, RequestInterrupt: true,
		ServicePublicKey: base64.RawURLEncoding.EncodeToString(workerKey),
	})
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, "/v1/service-admission-grants", bytes.NewReader(body))
	response := httptest.NewRecorder()
	api.handleServiceAdmissionGrant(response, request, service)
	if response.Code != http.StatusCreated || response.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("grant response = status %d headers %#v", response.Code, response.Header())
	}
	var issued managementServiceAdmissionGrantResponse
	if err := json.NewDecoder(response.Result().Body).Decode(&issued); err != nil {
		t.Fatal(err)
	}
	if issued.Grant == "" || issued.ExpiresAt == "" {
		t.Fatalf("grant response body = %#v", issued)
	}

	deniedBody, err := json.Marshal(managementServiceAdmissionGrantRequest{
		ChannelID: 100, SenderID: 9001, Role: "automation", RequestInterrupt: true,
		ServicePublicKey: base64.RawURLEncoding.EncodeToString(workerKey),
	})
	if err != nil {
		t.Fatal(err)
	}
	deniedRequest := httptest.NewRequest(http.MethodPost, "/v1/service-admission-grants", bytes.NewReader(deniedBody))
	deniedResponse := httptest.NewRecorder()
	api.handleServiceAdmissionGrant(deniedResponse, deniedRequest, service)
	if deniedResponse.Code != http.StatusBadRequest {
		t.Fatalf("interrupt without talk status = %d", deniedResponse.Code)
	}
}

func TestManagementAPIServiceAdmissionRevocationRequiresAdminAndPCLAck(t *testing.T) {
	issuer := newTestServiceAdmissionGrantIssuer(t)
	grantHash := issueTestServiceAdmissionGrant(t, issuer)
	denyUntil := time.Now().Add(time.Minute).Unix()
	revoker := &fakeManagementServiceAdmissionRevoker{ack: privateControlAck{
		Outcome: "applied", DenyUntil: denyUntil, AffectedMembershipCount: 2, TalkReleaseCount: 1,
	}}
	api := &managementAPI{issuer: issuer, revoker: revoker}
	admin := &managementAPIService{
		serviceID: "management-admin", apiRole: "admin", enabled: true,
		globalPermissions: map[string]struct{}{managementAPIRevokePermission: {}},
	}
	body, err := json.Marshal(managementServiceAdmissionRevocationRequest{
		ChannelID: 100, GrantIDHash: grantHash, Reason: "grant_revoked", DenyUntil: denyUntil,
	})
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, "/v1/service-admission-revocations", bytes.NewReader(body))
	response := httptest.NewRecorder()
	api.handleServiceAdmissionRevocation(response, request, admin)
	if response.Code != http.StatusOK || revoker.request.GrantIDHash != grantHash {
		t.Fatalf("revocation response/request = %d/%#v", response.Code, revoker.request)
	}
	var acknowledged managementServiceAdmissionRevocationResponse
	if err := json.NewDecoder(response.Result().Body).Decode(&acknowledged); err != nil {
		t.Fatal(err)
	}
	if acknowledged.Outcome != "applied" || acknowledged.AffectedMembershipCount != 2 || acknowledged.TalkReleaseCount != 1 {
		t.Fatalf("revocation acknowledgement = %#v", acknowledged)
	}

	nonAdmin := &managementAPIService{serviceID: "recorder-01", apiRole: "recorder", globalPermissions: map[string]struct{}{managementAPIRevokePermission: {}}}
	forbiddenResponse := httptest.NewRecorder()
	api.handleServiceAdmissionRevocation(forbiddenResponse, request.Clone(context.Background()), nonAdmin)
	if forbiddenResponse.Code != http.StatusForbidden {
		t.Fatalf("non-admin revocation status = %d", forbiddenResponse.Code)
	}
}

func TestManagementAPIServiceAdmissionRevocationReturnsPendingWhenPCLAckIsDelayed(t *testing.T) {
	denyUntil := time.Now().Add(time.Minute).Unix()
	api := &managementAPI{revoker: &fakeManagementServiceAdmissionRevoker{err: context.DeadlineExceeded}}
	admin := &managementAPIService{
		serviceID: "management-admin", apiRole: "admin", enabled: true,
		globalPermissions: map[string]struct{}{managementAPIRevokePermission: {}},
	}
	body, err := json.Marshal(managementServiceAdmissionRevocationRequest{
		ChannelID: 100, ServiceID: "recorder-01", Reason: "service_disabled", DenyUntil: denyUntil,
	})
	if err != nil {
		t.Fatal(err)
	}
	response := httptest.NewRecorder()
	api.handleServiceAdmissionRevocation(response, httptest.NewRequest(http.MethodPost, "/v1/service-admission-revocations", bytes.NewReader(body)), admin)
	if response.Code != http.StatusAccepted {
		t.Fatalf("pending revocation status = %d", response.Code)
	}
	var pending managementServiceAdmissionRevocationPendingResponse
	if err := json.NewDecoder(response.Result().Body).Decode(&pending); err != nil {
		t.Fatal(err)
	}
	if pending.Status != "pending_relay_ack" || pending.DenyUntil != denyUntil || pending.MessageID == "" {
		t.Fatalf("pending revocation response = %#v", pending)
	}
}

func newTestServiceAdmissionGrantIssuer(t *testing.T) *serviceAdmissionGrantIssuer {
	t.Helper()
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return &serviceAdmissionGrantIssuer{
		privateKey: privateKey, keyID: "test-key", issuer: "https://management.test", audience: "relay-test", lifetime: 5 * time.Minute,
		issued: make(map[string]issuedServiceAdmissionGrant),
	}
}

func issueTestServiceAdmissionGrant(t *testing.T, issuer *serviceAdmissionGrantIssuer) string {
	t.Helper()
	workerKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	grant, _, err := issuer.issue("recorder-01", managementAdmissionACL{role: "recorder", allowListen: true, enabled: true}, managementServiceAdmissionGrantRequest{
		ChannelID: 100, SenderID: 9001, Role: "recorder", ServicePublicKey: base64.RawURLEncoding.EncodeToString(workerKey),
	}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	segments := strings.Split(grant, ".")
	payload, err := base64.RawURLEncoding.DecodeString(segments[1])
	if err != nil {
		t.Fatal(err)
	}
	var claims serviceAdmissionGrantClaims
	if err := json.Unmarshal(payload, &claims); err != nil {
		t.Fatal(err)
	}
	hash := sha256.Sum256([]byte(claims.GrantID))
	return base64.RawURLEncoding.EncodeToString(hash[:])
}

type fakeManagementServiceAdmissionRevoker struct {
	ack     privateControlAck
	request managementServiceAdmissionRevocationRequest
	err     error
}

func (r *fakeManagementServiceAdmissionRevoker) revokeServiceAdmission(_ context.Context, request managementServiceAdmissionRevocationRequest) (privateControlAck, string, error) {
	r.request = request
	return r.ack, "MDEyMzQ1Njc4OTo7PD0-Pw", r.err
}
