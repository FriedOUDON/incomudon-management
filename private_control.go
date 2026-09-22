package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"path"
	"regexp"
	"strings"
	"time"
)

const (
	privateControlSchemaVersion    = "private-control-link-v1"
	privateControlMaxFrameBytes    = 65536
	privateControlTLSMinVersion    = tls.VersionTLS13
	privateControlTransportMTLSTCP = "mtls-tcp"
	privateControlTransportUDS     = "uds"
)

var privateControlEventNamePattern = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)

type privateControlClientConfig struct {
	transport       string
	relayAddress    string
	udsSocketPath   string
	serverName      string
	serviceID       string
	certificateFile string
	privateKeyFile  string
	relayCAFile     string
}

type privateControlClient struct {
	config    privateControlClientConfig
	tlsConfig *tls.Config
	state     *managementState
}

type privateControlHello struct {
	SchemaVersion       string `json:"schema_version"`
	Type                string `json:"type"`
	MessageID           string `json:"message_id"`
	ManagementServiceID string `json:"management_service_id"`
	WantLifecycleEvents *bool  `json:"want_lifecycle_events"`
	WantAuditInputs     *bool  `json:"want_audit_inputs"`
	WantDiagnostics     *bool  `json:"want_diagnostics"`
}

type privateControlHelloAck struct {
	SchemaVersion           string `json:"schema_version"`
	Type                    string `json:"type"`
	MessageID               string `json:"message_id"`
	InReplyTo               string `json:"in_reply_to"`
	SessionID               string `json:"session_id"`
	RelayID                 string `json:"relay_id"`
	LifecycleEventsAccepted *bool  `json:"lifecycle_events_accepted"`
	AuditInputsAccepted     *bool  `json:"audit_inputs_accepted"`
	DiagnosticsAccepted     *bool  `json:"diagnostics_accepted"`
}

type privateControlEnvelope struct {
	SchemaVersion string `json:"schema_version"`
	Type          string `json:"type"`
	MessageID     string `json:"message_id"`
}

type privateControlError struct {
	SchemaVersion string `json:"schema_version"`
	Type          string `json:"type"`
	MessageID     string `json:"message_id"`
	InReplyTo     string `json:"in_reply_to,omitempty"`
	Code          string `json:"code"`
}

type privateControlLifecycleEvent struct {
	SchemaVersion  string  `json:"schema_version"`
	Type           string  `json:"type"`
	MessageID      string  `json:"message_id"`
	OccurredAt     string  `json:"occurred_at"`
	EventType      string  `json:"event_type"`
	ChannelID      *uint32 `json:"channel_id"`
	SenderID       *uint32 `json:"sender_id,omitempty"`
	ServiceID      *string `json:"service_id,omitempty"`
	RecordingJobID *string `json:"recording_job_id,omitempty"`
	State          *string `json:"state,omitempty"`
	Reason         *string `json:"reason,omitempty"`
}

func newPrivateControlClient(config privateControlClientConfig, state *managementState) (*privateControlClient, error) {
	if state == nil || !validManagementServiceID(config.serviceID) {
		return nil, errors.New("Management Service ID is required")
	}
	client := &privateControlClient{config: config, state: state}
	switch config.transport {
	case privateControlTransportMTLSTCP:
		if strings.TrimSpace(config.relayAddress) == "" || strings.TrimSpace(config.serverName) == "" ||
			strings.TrimSpace(config.certificateFile) == "" || strings.TrimSpace(config.privateKeyFile) == "" || strings.TrimSpace(config.relayCAFile) == "" {
			return nil, errors.New("mTLS Relay address, server name, client certificate/key, and Relay CA are required")
		}
		certificate, err := tls.LoadX509KeyPair(config.certificateFile, config.privateKeyFile)
		if err != nil {
			return nil, fmt.Errorf("load Management Service client certificate: %w", err)
		}
		caData, err := os.ReadFile(config.relayCAFile)
		if err != nil {
			return nil, fmt.Errorf("read Relay CA: %w", err)
		}
		roots := x509.NewCertPool()
		if !roots.AppendCertsFromPEM(caData) {
			return nil, errors.New("Relay CA contains no certificates")
		}
		client.tlsConfig = &tls.Config{
			MinVersion:   privateControlTLSMinVersion,
			Certificates: []tls.Certificate{certificate},
			RootCAs:      roots,
			ServerName:   config.serverName,
		}
	case privateControlTransportUDS:
		if !path.IsAbs(config.udsSocketPath) {
			return nil, errors.New("UDS socket path must be absolute")
		}
	default:
		return nil, fmt.Errorf("Private Control Link transport must be %q or %q", privateControlTransportUDS, privateControlTransportMTLSTCP)
	}
	return client, nil
}

func (c *privateControlClient) run(context context.Context) {
	retry := time.Second
	for context.Err() == nil {
		err := c.runSession(context)
		c.state.markDisconnected()
		if context.Err() != nil {
			return
		}
		log.Printf("Private Control Link disconnected: %v; retrying in %s", err, retry)
		timer := time.NewTimer(retry)
		select {
		case <-context.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
		if retry < 30*time.Second {
			retry *= 2
			if retry > 30*time.Second {
				retry = 30 * time.Second
			}
		}
	}
}

func (c *privateControlClient) runSession(context context.Context) error {
	var (
		connection net.Conn
		err        error
	)
	switch c.config.transport {
	case privateControlTransportMTLSTCP:
		dialer := &tls.Dialer{NetDialer: &net.Dialer{Timeout: 5 * time.Second}, Config: c.tlsConfig}
		connection, err = dialer.DialContext(context, "tcp", c.config.relayAddress)
	case privateControlTransportUDS:
		connection, err = (&net.Dialer{Timeout: 5 * time.Second}).DialContext(context, "unix", c.config.udsSocketPath)
	default:
		return fmt.Errorf("unsupported Private Control Link transport %q", c.config.transport)
	}
	if err != nil {
		return err
	}
	defer connection.Close()
	sessionDone := make(chan struct{})
	go func() {
		select {
		case <-context.Done():
			_ = connection.Close()
		case <-sessionDone:
		}
	}()
	defer close(sessionDone)

	messageID, err := newPrivateControlID()
	if err != nil {
		return err
	}
	wantEvents, wantAuditInputs, wantDiagnostics := true, false, false
	if err := writePrivateControlFrame(connection, privateControlHello{
		SchemaVersion:       privateControlSchemaVersion,
		Type:                "hello",
		MessageID:           messageID,
		ManagementServiceID: c.config.serviceID,
		WantLifecycleEvents: &wantEvents,
		WantAuditInputs:     &wantAuditInputs,
		WantDiagnostics:     &wantDiagnostics,
	}); err != nil {
		return err
	}
	rawAck, err := readPrivateControlFrame(connection)
	if err != nil {
		return err
	}
	var ack privateControlHelloAck
	if err := decodePrivateControlJSON(rawAck, &ack); err != nil {
		return err
	}
	if !validPrivateControlHelloAck(ack, messageID) {
		return errors.New("invalid Private Control Link hello_ack")
	}
	if !*ack.LifecycleEventsAccepted {
		return errors.New("Relay rejected lifecycle event export")
	}
	if *ack.AuditInputsAccepted {
		return errors.New("Relay accepted unsupported audit inputs")
	}
	if *ack.DiagnosticsAccepted {
		return errors.New("Relay accepted unsupported diagnostics")
	}
	c.state.markConnected(ack.RelayID)

	for {
		rawMessage, err := readPrivateControlFrame(connection)
		if err != nil {
			return err
		}
		envelope, err := decodePrivateControlEnvelope(rawMessage)
		if err != nil {
			return err
		}
		switch envelope.Type {
		case "relay_lifecycle_event":
			var event privateControlLifecycleEvent
			if err := decodePrivateControlJSON(rawMessage, &event); err != nil {
				return err
			}
			if !validPrivateControlLifecycleEvent(event) {
				return errors.New("invalid Relay lifecycle event")
			}
			c.state.recordLifecycleEvent(event)
		case "error":
			var response privateControlError
			if err := decodePrivateControlJSON(rawMessage, &response); err != nil {
				return err
			}
			if response.SchemaVersion != privateControlSchemaVersion || !validPrivateControlID(response.MessageID) || response.Code == "" {
				return errors.New("invalid Private Control Link error")
			}
			return fmt.Errorf("Relay Private Control Link error: %s", response.Code)
		default:
			return fmt.Errorf("unexpected Relay Private Control Link message type %q", envelope.Type)
		}
	}
}

func validManagementServiceID(value string) bool {
	if len(value) == 0 || len(value) > 128 {
		return false
	}
	return regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`).MatchString(value)
}

func newPrivateControlID() (string, error) {
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(raw[:]), nil
}

func validPrivateControlID(value string) bool {
	if len(value) != 22 {
		return false
	}
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	return err == nil && len(decoded) == 16 && base64.RawURLEncoding.EncodeToString(decoded) == value
}

func validPrivateControlHelloAck(ack privateControlHelloAck, inReplyTo string) bool {
	return ack.SchemaVersion == privateControlSchemaVersion && ack.Type == "hello_ack" &&
		validPrivateControlID(ack.MessageID) && ack.InReplyTo == inReplyTo &&
		validPrivateControlID(ack.SessionID) && strings.TrimSpace(ack.RelayID) != "" && len(ack.RelayID) <= 128 &&
		ack.LifecycleEventsAccepted != nil && ack.AuditInputsAccepted != nil && ack.DiagnosticsAccepted != nil
}

func validPrivateControlLifecycleEvent(event privateControlLifecycleEvent) bool {
	if event.SchemaVersion != privateControlSchemaVersion || event.Type != "relay_lifecycle_event" ||
		!validPrivateControlID(event.MessageID) || !privateControlEventNamePattern.MatchString(event.EventType) {
		return false
	}
	_, err := time.Parse(time.RFC3339, event.OccurredAt)
	return err == nil
}

func decodePrivateControlEnvelope(raw []byte) (privateControlEnvelope, error) {
	var envelope privateControlEnvelope
	if err := json.Unmarshal(raw, &envelope); err != nil {
		return privateControlEnvelope{}, err
	}
	if envelope.SchemaVersion != privateControlSchemaVersion || envelope.Type == "" || !validPrivateControlID(envelope.MessageID) {
		return privateControlEnvelope{}, errors.New("invalid Private Control Link message envelope")
	}
	return envelope, nil
}

func readPrivateControlFrame(reader io.Reader) ([]byte, error) {
	var lengthBytes [4]byte
	if _, err := io.ReadFull(reader, lengthBytes[:]); err != nil {
		return nil, err
	}
	length := binary.BigEndian.Uint32(lengthBytes[:])
	if length < 2 || length > privateControlMaxFrameBytes {
		return nil, errors.New("invalid Private Control Link frame length")
	}
	payload := make([]byte, length)
	if _, err := io.ReadFull(reader, payload); err != nil {
		return nil, err
	}
	if err := validatePrivateControlJSON(payload); err != nil {
		return nil, fmt.Errorf("invalid Private Control Link JSON: %w", err)
	}
	return payload, nil
}

func writePrivateControlFrame(writer io.Writer, value any) error {
	payload, err := json.Marshal(value)
	if err != nil {
		return err
	}
	if len(payload) < 2 || len(payload) > privateControlMaxFrameBytes {
		return errors.New("invalid Private Control Link outgoing frame size")
	}
	var lengthBytes [4]byte
	binary.BigEndian.PutUint32(lengthBytes[:], uint32(len(payload)))
	if err := writePrivateControlBytes(writer, lengthBytes[:]); err != nil {
		return err
	}
	return writePrivateControlBytes(writer, payload)
}

func writePrivateControlBytes(writer io.Writer, payload []byte) error {
	for len(payload) > 0 {
		written, err := writer.Write(payload)
		if err != nil {
			return err
		}
		if written <= 0 {
			return io.ErrShortWrite
		}
		payload = payload[written:]
	}
	return nil
}

func decodePrivateControlJSON(raw []byte, target any) error {
	if err := validatePrivateControlJSON(raw); err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	if err := requireJSONEOF(decoder); err != nil {
		return err
	}
	return nil
}

func validatePrivateControlJSON(raw []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	if err := scanPrivateControlJSONValue(decoder); err != nil {
		return err
	}
	return requireJSONEOF(decoder)
}

func requireJSONEOF(decoder *json.Decoder) error {
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("multiple JSON values")
		}
		return err
	}
	return nil
}

func scanPrivateControlJSONValue(decoder *json.Decoder) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delimiter, isDelimiter := token.(json.Delim)
	if !isDelimiter {
		return nil
	}
	switch delimiter {
	case '{':
		seen := make(map[string]struct{})
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return err
			}
			key, ok := keyToken.(string)
			if !ok {
				return errors.New("JSON object key is not a string")
			}
			if _, duplicate := seen[key]; duplicate {
				return fmt.Errorf("duplicate JSON object member %q", key)
			}
			seen[key] = struct{}{}
			if err := scanPrivateControlJSONValue(decoder); err != nil {
				return err
			}
		}
		closing, err := decoder.Token()
		if err != nil || closing != json.Delim('}') {
			if err != nil {
				return err
			}
			return errors.New("JSON object is not closed")
		}
	case '[':
		for decoder.More() {
			if err := scanPrivateControlJSONValue(decoder); err != nil {
				return err
			}
		}
		closing, err := decoder.Token()
		if err != nil || closing != json.Delim(']') {
			if err != nil {
				return err
			}
			return errors.New("JSON array is not closed")
		}
	default:
		return errors.New("unexpected JSON delimiter")
	}
	return nil
}
