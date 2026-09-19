package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestPrivateControlClientConsumesRelayLifecycleEvent(t *testing.T) {
	serverConfig, clientConfig := newPrivateControlTestCredentials(t)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	clientConfig.relayAddress = listener.Addr().String()

	serverDone := make(chan error, 1)
	go func() {
		rawConnection, err := listener.Accept()
		if err != nil {
			serverDone <- err
			return
		}
		connection := tls.Server(rawConnection, serverConfig)
		defer connection.Close()
		if err := connection.Handshake(); err != nil {
			serverDone <- err
			return
		}
		rawHello, err := readPrivateControlFrame(connection)
		if err != nil {
			serverDone <- err
			return
		}
		var hello privateControlHello
		if err := decodePrivateControlJSON(rawHello, &hello); err != nil {
			serverDone <- err
			return
		}
		if hello.SchemaVersion != privateControlSchemaVersion || hello.Type != "hello" || hello.ManagementServiceID != clientConfig.serviceID || hello.WantLifecycleEvents == nil || !*hello.WantLifecycleEvents || hello.WantAuditInputs == nil || *hello.WantAuditInputs {
			serverDone <- errUnexpectedPrivateControlHello
			return
		}
		ackID, err := newPrivateControlID()
		if err != nil {
			serverDone <- err
			return
		}
		sessionID, err := newPrivateControlID()
		if err != nil {
			serverDone <- err
			return
		}
		if err := writePrivateControlFrame(connection, privateControlHelloAck{
			SchemaVersion:           privateControlSchemaVersion,
			Type:                    "hello_ack",
			MessageID:               ackID,
			InReplyTo:               hello.MessageID,
			SessionID:               sessionID,
			RelayID:                 "relay-test",
			LifecycleEventsAccepted: true,
			AuditInputsAccepted:     false,
		}); err != nil {
			serverDone <- err
			return
		}
		eventID, err := newPrivateControlID()
		if err != nil {
			serverDone <- err
			return
		}
		if err := writePrivateControlFrame(connection, privateControlLifecycleEvent{
			SchemaVersion: privateControlSchemaVersion,
			Type:          "relay_lifecycle_event",
			MessageID:     eventID,
			OccurredAt:    time.Now().UTC().Format(time.RFC3339),
			EventType:     "relay_health_changed",
			State:         stringPointer("healthy"),
		}); err != nil {
			serverDone <- err
			return
		}
		serverDone <- nil
	}()

	state := &managementState{}
	client, err := newPrivateControlClient(clientConfig, state)
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	if err := client.runSession(context.Background()); err == nil {
		t.Fatal("session unexpectedly ended without an error")
	}
	if err := <-serverDone; err != nil {
		t.Fatalf("test Relay: %v", err)
	}
	snapshot := state.snapshot()
	if snapshot["status"] != "connected" || snapshot["relay_id"] != "relay-test" || snapshot["last_event_type"] != "relay_health_changed" {
		t.Fatalf("unexpected client state: %#v", snapshot)
	}
}

var errUnexpectedPrivateControlHello = &privateControlTestError{"unexpected Private Control Link hello"}

type privateControlTestError struct {
	message string
}

func (e *privateControlTestError) Error() string { return e.message }

func newPrivateControlTestCredentials(t *testing.T) (*tls.Config, privateControlClientConfig) {
	t.Helper()
	now := time.Now()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("create CA key: %v", err)
	}
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("create CA certificate: %v", err)
	}
	caCertificate, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatalf("parse CA certificate: %v", err)
	}
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})
	serverCertificate, _, _ := newPrivateControlTestLeaf(t, caCertificate, caKey, 2, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, []string{"relay.test"})
	_, clientCertificatePEM, clientKeyPEM := newPrivateControlTestLeaf(t, caCertificate, caKey, 3, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, nil)
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(caPEM) {
		t.Fatal("append test CA")
	}

	dataDirectory := t.TempDir()
	certificatePath := filepath.Join(dataDirectory, "client.crt")
	privateKeyPath := filepath.Join(dataDirectory, "client.key")
	caPath := filepath.Join(dataDirectory, "relay-ca.crt")
	for path, data := range map[string][]byte{certificatePath: clientCertificatePEM, privateKeyPath: clientKeyPEM, caPath: caPEM} {
		if err := os.WriteFile(path, data, 0600); err != nil {
			t.Fatalf("write %s: %v", path, err)
		}
	}
	return &tls.Config{
			MinVersion:   tls.VersionTLS13,
			Certificates: []tls.Certificate{serverCertificate},
			ClientAuth:   tls.RequireAndVerifyClientCert,
			ClientCAs:    roots,
		}, privateControlClientConfig{
			serverName:      "relay.test",
			serviceID:       "management-main",
			certificateFile: certificatePath,
			privateKeyFile:  privateKeyPath,
			relayCAFile:     caPath,
		}
}

func newPrivateControlTestLeaf(t *testing.T, issuer *x509.Certificate, issuerKey *ecdsa.PrivateKey, serial int64, usages []x509.ExtKeyUsage, dnsNames []string) (tls.Certificate, []byte, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("create leaf key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(serial),
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  usages,
		DNSNames:     dnsNames,
	}
	certificateDER, err := x509.CreateCertificate(rand.Reader, template, issuer, &key.PublicKey, issuerKey)
	if err != nil {
		t.Fatalf("create leaf certificate: %v", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("marshal leaf key: %v", err)
	}
	certificatePEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificateDER})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	certificate, err := tls.X509KeyPair(certificatePEM, keyPEM)
	if err != nil {
		t.Fatalf("load leaf key pair: %v", err)
	}
	return certificate, certificatePEM, keyPEM
}

func stringPointer(value string) *string { return &value }
