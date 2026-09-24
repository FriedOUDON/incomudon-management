package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	serviceAdmissionGrantMinimumLifetime = 60 * time.Second
	serviceAdmissionGrantMaximumLifetime = time.Hour
	serviceAdmissionGrantDefaultLifetime = 5 * time.Minute
	serviceAdmissionGrantMaximumBytes    = 768
	serviceAdmissionGrantMaximumTracked  = 4096
)

var (
	serviceAdmissionGrantKeyIDPattern = regexp.MustCompile(`^[A-Za-z0-9._-]{1,128}$`)
	errServiceAdmissionGrantTracking  = fmt.Errorf("Service Admission grant tracking capacity reached")
)

type serviceAdmissionGrantIssuer struct {
	privateKey ed25519.PrivateKey
	keyID      string
	issuer     string
	audience   string
	lifetime   time.Duration

	mu     sync.Mutex
	issued map[string]issuedServiceAdmissionGrant
}

type issuedServiceAdmissionGrant struct {
	serviceID string
	channelID uint32
	expiresAt time.Time
}

type serviceAdmissionGrantHeader struct {
	Algorithm string `json:"alg"`
	KeyID     string `json:"kid"`
	Type      string `json:"typ"`
}

type serviceAdmissionGrantConfirmation struct {
	JWKThumbprint string `json:"jkt"`
}

type serviceAdmissionGrantClaims struct {
	Issuer       string                            `json:"iss"`
	Audience     string                            `json:"aud"`
	ServiceID    string                            `json:"svc"`
	GrantID      string                            `json:"jti"`
	IssuedAt     int64                             `json:"iat"`
	ExpiresAt    int64                             `json:"exp"`
	ChannelID    uint32                            `json:"ch"`
	SenderID     uint32                            `json:"sid"`
	Role         string                            `json:"role"`
	Permissions  uint8                             `json:"perm"`
	Priority     *uint8                            `json:"pri,omitempty"`
	Confirmation serviceAdmissionGrantConfirmation `json:"cnf"`
}

func loadServiceAdmissionGrantIssuer(config managementAPIConfig) (*serviceAdmissionGrantIssuer, error) {
	values := []string{config.grantSigningKeyFile, config.grantKeyID, config.grantIssuer, config.grantAudience}
	configured := false
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			configured = true
			break
		}
	}
	if !configured {
		return nil, nil
	}
	for _, field := range []struct {
		name  string
		value string
	}{
		{"grant signing key", config.grantSigningKeyFile},
		{"grant key ID", config.grantKeyID},
		{"grant issuer", config.grantIssuer},
		{"grant audience", config.grantAudience},
	} {
		if strings.TrimSpace(field.value) == "" {
			return nil, fmt.Errorf("Management API %s is required when Service Admission issuance is configured", field.name)
		}
	}
	if !serviceAdmissionGrantKeyIDPattern.MatchString(config.grantKeyID) {
		return nil, fmt.Errorf("Management API grant key ID is invalid")
	}
	if !validServiceAdmissionIssuerValue(config.grantIssuer) || !validServiceAdmissionIssuerValue(config.grantAudience) {
		return nil, fmt.Errorf("Management API grant issuer or audience is invalid")
	}
	lifetime := serviceAdmissionGrantDefaultLifetime
	if value := strings.TrimSpace(config.grantTTLSeconds); value != "" {
		seconds, err := strconv.ParseInt(value, 10, 64)
		if err != nil || seconds < int64(serviceAdmissionGrantMinimumLifetime/time.Second) || seconds > int64(serviceAdmissionGrantMaximumLifetime/time.Second) {
			return nil, fmt.Errorf("Management API grant TTL must be an integer from 60 through 3600 seconds")
		}
		lifetime = time.Duration(seconds) * time.Second
	}
	key, err := loadServiceAdmissionSigningKey(config.grantSigningKeyFile)
	if err != nil {
		return nil, err
	}
	return &serviceAdmissionGrantIssuer{
		privateKey: key,
		keyID:      config.grantKeyID,
		issuer:     config.grantIssuer,
		audience:   config.grantAudience,
		lifetime:   lifetime,
		issued:     make(map[string]issuedServiceAdmissionGrant),
	}, nil
}

func loadServiceAdmissionSigningKey(filename string) (ed25519.PrivateKey, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("read Service Admission signing key: %w", err)
	}
	block, remaining := pem.Decode(data)
	if block == nil || block.Type != "PRIVATE KEY" || strings.TrimSpace(string(remaining)) != "" {
		return nil, fmt.Errorf("Service Admission signing key must be one unencrypted PKCS#8 PRIVATE KEY PEM block")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse Service Admission signing key: %w", err)
	}
	key, ok := parsed.(ed25519.PrivateKey)
	if !ok || len(key) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("Service Admission signing key must be Ed25519")
	}
	return append(ed25519.PrivateKey(nil), key...), nil
}

func validServiceAdmissionIssuerValue(value string) bool {
	return len(value) >= 1 && len(value) <= 256 && strings.TrimSpace(value) == value
}

func (i *serviceAdmissionGrantIssuer) issue(serviceID string, acl managementAdmissionACL, request managementServiceAdmissionGrantRequest, now time.Time) (string, time.Time, error) {
	if i == nil || !validManagementServiceID(serviceID) || !acl.enabled || acl.role != request.Role || !acl.allowListen {
		return "", time.Time{}, fmt.Errorf("grant request is not authorized by the channel ACL")
	}
	if request.RequestTalk && !acl.allowTalk {
		return "", time.Time{}, fmt.Errorf("channel ACL does not permit talk")
	}
	if request.RequestInterrupt && (!request.RequestTalk || !acl.allowInterrupt || acl.interruptPriority == 0) {
		return "", time.Time{}, fmt.Errorf("channel ACL does not permit interrupt")
	}
	publicKey, err := decodeServiceAdmissionPublicKey(request.ServicePublicKey)
	if err != nil {
		return "", time.Time{}, err
	}
	grantID, err := newServiceAdmissionGrantID()
	if err != nil {
		return "", time.Time{}, err
	}
	permissions := uint8(1)
	if request.RequestTalk {
		permissions |= 2
	}
	var priority *uint8
	if request.RequestInterrupt {
		permissions |= 4
		value := acl.interruptPriority
		priority = &value
	}
	issuedAt := now.UTC().Truncate(time.Second)
	expiresAt := issuedAt.Add(i.lifetime)
	thumbprint := sha256.Sum256(publicKey)
	claims := serviceAdmissionGrantClaims{
		Issuer:      i.issuer,
		Audience:    i.audience,
		ServiceID:   serviceID,
		GrantID:     grantID,
		IssuedAt:    issuedAt.Unix(),
		ExpiresAt:   expiresAt.Unix(),
		ChannelID:   request.ChannelID,
		SenderID:    request.SenderID,
		Role:        request.Role,
		Permissions: permissions,
		Priority:    priority,
		Confirmation: serviceAdmissionGrantConfirmation{
			JWKThumbprint: base64.RawURLEncoding.EncodeToString(thumbprint[:]),
		},
	}
	grant, err := signServiceAdmissionGrant(i.privateKey, i.keyID, claims)
	if err != nil {
		return "", time.Time{}, err
	}
	grantIDHash := sha256.Sum256([]byte(grantID))
	encodedGrantIDHash := base64.RawURLEncoding.EncodeToString(grantIDHash[:])
	i.mu.Lock()
	i.cleanupIssuedLocked(issuedAt)
	if len(i.issued) >= serviceAdmissionGrantMaximumTracked {
		i.mu.Unlock()
		return "", time.Time{}, errServiceAdmissionGrantTracking
	}
	i.issued[encodedGrantIDHash] = issuedServiceAdmissionGrant{serviceID: serviceID, channelID: request.ChannelID, expiresAt: expiresAt}
	i.mu.Unlock()
	return grant, expiresAt, nil
}

func (i *serviceAdmissionGrantIssuer) issuedGrant(grantIDHash string, now time.Time) (issuedServiceAdmissionGrant, bool) {
	if i == nil {
		return issuedServiceAdmissionGrant{}, false
	}
	i.mu.Lock()
	defer i.mu.Unlock()
	i.cleanupIssuedLocked(now)
	grant, found := i.issued[grantIDHash]
	return grant, found
}

func (i *serviceAdmissionGrantIssuer) cleanupIssuedLocked(now time.Time) {
	for grantIDHash, grant := range i.issued {
		if !grant.expiresAt.After(now) {
			delete(i.issued, grantIDHash)
		}
	}
}

func decodeServiceAdmissionPublicKey(value string) (ed25519.PublicKey, error) {
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil || len(decoded) != ed25519.PublicKeySize || base64.RawURLEncoding.EncodeToString(decoded) != value {
		return nil, fmt.Errorf("service_public_key must be canonical Base64URL-encoded raw Ed25519 public key")
	}
	return ed25519.PublicKey(append([]byte(nil), decoded...)), nil
}

func newServiceAdmissionGrantID() (string, error) {
	var raw [24]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(raw[:]), nil
}

func signServiceAdmissionGrant(privateKey ed25519.PrivateKey, keyID string, claims serviceAdmissionGrantClaims) (string, error) {
	header, err := json.Marshal(serviceAdmissionGrantHeader{Algorithm: "EdDSA", KeyID: keyID, Type: "incomudon-service-admission+jwt"})
	if err != nil {
		return "", err
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	protected := base64.RawURLEncoding.EncodeToString(header)
	body := base64.RawURLEncoding.EncodeToString(payload)
	signingInput := protected + "." + body
	signature := ed25519.Sign(privateKey, []byte(signingInput))
	grant := signingInput + "." + base64.RawURLEncoding.EncodeToString(signature)
	if len(grant) > serviceAdmissionGrantMaximumBytes {
		return "", fmt.Errorf("Service Admission grant exceeds %d bytes", serviceAdmissionGrantMaximumBytes)
	}
	return grant, nil
}
