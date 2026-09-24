package main

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"testing"
	"time"
)

func TestPrivateControlIDRequiresCanonicalBase64URL(t *testing.T) {
	id, err := newPrivateControlID()
	if err != nil {
		t.Fatalf("new ID: %v", err)
	}
	if !validPrivateControlID(id) {
		t.Fatalf("generated ID is invalid: %q", id)
	}
	if validPrivateControlID("AAAAAAAAAAAAAAAAAAAAAB") {
		t.Fatal("noncanonical Base64URL ID was accepted")
	}
}

func TestPrivateControlFrameRejectsDuplicateJSONMembers(t *testing.T) {
	payload := []byte(`{"schema_version":"private-control-link-v1","schema_version":"private-control-link-v1"}`)
	var frame bytes.Buffer
	var length [4]byte
	binary.BigEndian.PutUint32(length[:], uint32(len(payload)))
	frame.Write(length[:])
	frame.Write(payload)
	if _, err := readPrivateControlFrame(&frame); err == nil {
		t.Fatal("duplicate JSON member was accepted")
	}
}

func TestPrivateControlLifecycleEventValidation(t *testing.T) {
	id, err := newPrivateControlID()
	if err != nil {
		t.Fatalf("new ID: %v", err)
	}
	channelID := uint32(100)
	event := privateControlLifecycleEvent{
		SchemaVersion: privateControlSchemaVersion,
		Type:          "relay_lifecycle_event",
		MessageID:     id,
		OccurredAt:    time.Now().UTC().Format(time.RFC3339),
		EventType:     "talk_started",
		ChannelID:     &channelID,
	}
	if !privateControlLifecycleEventIsValid(t, event) {
		t.Fatal("valid lifecycle event was rejected")
	}
	event.EventType = "unrecognized_event"
	if privateControlLifecycleEventIsValid(t, event) {
		t.Fatal("unrecognized lifecycle event was accepted")
	}
}

func TestPrivateControlLifecycleEventRejectsSchemaViolations(t *testing.T) {
	const messageID = "AAAAAAAAAAAAAAAAAAAAAA"
	channelID := uint32(100)
	zeroSenderID := uint32(0)
	healthy := "healthy"
	invalidServiceID := "service:invalid"
	empty := ""
	lowercaseReason := "membership_timeout"
	nonUTCTimestamp := "2026-01-01T00:00:00+09:00"

	tests := []struct {
		name  string
		event privateControlLifecycleEvent
	}{
		{
			name: "non-health event with null channel", event: privateControlLifecycleEvent{
				SchemaVersion: privateControlSchemaVersion, Type: "relay_lifecycle_event", MessageID: messageID,
				OccurredAt: time.Now().UTC().Format(time.RFC3339), EventType: "talk_started",
			},
		},
		{
			name: "health event with channel", event: privateControlLifecycleEvent{
				SchemaVersion: privateControlSchemaVersion, Type: "relay_lifecycle_event", MessageID: messageID,
				OccurredAt: time.Now().UTC().Format(time.RFC3339), EventType: "relay_health_changed", ChannelID: &channelID, State: &healthy,
			},
		},
		{
			name: "health event without state", event: privateControlLifecycleEvent{
				SchemaVersion: privateControlSchemaVersion, Type: "relay_lifecycle_event", MessageID: messageID,
				OccurredAt: time.Now().UTC().Format(time.RFC3339), EventType: "relay_health_changed",
			},
		},
		{
			name: "zero sender ID", event: privateControlLifecycleEvent{
				SchemaVersion: privateControlSchemaVersion, Type: "relay_lifecycle_event", MessageID: messageID,
				OccurredAt: time.Now().UTC().Format(time.RFC3339), EventType: "talk_started", ChannelID: &channelID, SenderID: &zeroSenderID,
			},
		},
		{
			name: "invalid service ID", event: privateControlLifecycleEvent{
				SchemaVersion: privateControlSchemaVersion, Type: "relay_lifecycle_event", MessageID: messageID,
				OccurredAt: time.Now().UTC().Format(time.RFC3339), EventType: "talk_started", ChannelID: &channelID, ServiceID: &invalidServiceID,
			},
		},
		{
			name: "empty recording job ID", event: privateControlLifecycleEvent{
				SchemaVersion: privateControlSchemaVersion, Type: "relay_lifecycle_event", MessageID: messageID,
				OccurredAt: time.Now().UTC().Format(time.RFC3339), EventType: "recording_state_changed", ChannelID: &channelID, RecordingJobID: &empty,
			},
		},
		{
			name: "lowercase reason", event: privateControlLifecycleEvent{
				SchemaVersion: privateControlSchemaVersion, Type: "relay_lifecycle_event", MessageID: messageID,
				OccurredAt: time.Now().UTC().Format(time.RFC3339), EventType: "talk_ended", ChannelID: &channelID, Reason: &lowercaseReason,
			},
		},
		{
			name: "non-UTC timestamp", event: privateControlLifecycleEvent{
				SchemaVersion: privateControlSchemaVersion, Type: "relay_lifecycle_event", MessageID: messageID,
				OccurredAt: nonUTCTimestamp, EventType: "talk_started", ChannelID: &channelID,
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if privateControlLifecycleEventIsValid(t, test.event) {
				t.Fatal("schema-invalid lifecycle event was accepted")
			}
		})
	}

	raw, err := json.Marshal(map[string]any{
		"schema_version": privateControlSchemaVersion,
		"type":           "relay_lifecycle_event",
		"message_id":     messageID,
		"occurred_at":    time.Now().UTC().Format(time.RFC3339),
		"event_type":     "talk_started",
	})
	if err != nil {
		t.Fatal(err)
	}
	var missingChannel privateControlLifecycleEvent
	if err := decodePrivateControlJSON(raw, &missingChannel); err != nil {
		t.Fatal(err)
	}
	if validPrivateControlLifecycleEvent(raw, missingChannel) {
		t.Fatal("lifecycle event without channel_id was accepted")
	}
}

func TestPrivateControlErrorValidation(t *testing.T) {
	const messageID = "AAAAAAAAAAAAAAAAAAAAAA"
	response := privateControlError{
		SchemaVersion: privateControlSchemaVersion,
		Type:          "error",
		MessageID:     messageID,
		InReplyTo:     messageID,
		Code:          "overloaded",
	}
	if !validPrivateControlError(response) {
		t.Fatal("valid error response was rejected")
	}
	response.Code = "unexpected_error"
	if validPrivateControlError(response) {
		t.Fatal("unknown error code was accepted")
	}
	response.Code = "overloaded"
	response.InReplyTo = "not-a-private-control-id"
	if validPrivateControlError(response) {
		t.Fatal("invalid in_reply_to was accepted")
	}
}

func TestPrivateControlJSONRejectsMalformedUTF8(t *testing.T) {
	if err := validatePrivateControlJSON([]byte{'{', '"', 'x', '"', ':', '"', 0xff, '"', '}'}); err == nil {
		t.Fatal("malformed UTF-8 was accepted")
	}
}

func privateControlLifecycleEventIsValid(t *testing.T, event privateControlLifecycleEvent) bool {
	t.Helper()
	raw, err := json.Marshal(event)
	if err != nil {
		t.Fatal(err)
	}
	return validPrivateControlLifecycleEvent(raw, event)
}

func TestPrivateControlStateSnapshotReassemblyAppliesAtomically(t *testing.T) {
	state := newManagementState()
	reassembly := &privateControlSnapshotReassembly{
		snapshotID: "AAAAAAAAAAAAAAAAAAAAAA",
		chunkCount: 2,
		chunks:     make(map[uint16][]privateControlSnapshotChannel),
	}
	second := privateControlRelayStateSnapshot{
		SnapshotID: "AAAAAAAAAAAAAAAAAAAAAA",
		ChunkIndex: 1,
		ChunkCount: 2,
		Channels: []privateControlSnapshotChannel{{
			ChannelID:    101,
			Participants: []privateControlSnapshotParticipant{},
		}},
	}
	complete, channels, err := reassembly.add(second)
	if err != nil || complete || channels != nil {
		t.Fatalf("incomplete snapshot result = complete:%v channels:%#v err:%v", complete, channels, err)
	}
	if _, found := state.snapshot()["channel_count"]; found {
		t.Fatal("incomplete snapshot changed the state projection")
	}

	first := privateControlRelayStateSnapshot{
		SnapshotID: "AAAAAAAAAAAAAAAAAAAAAA",
		ChunkIndex: 0,
		ChunkCount: 2,
		Channels: []privateControlSnapshotChannel{{
			ChannelID: 100,
			Participants: []privateControlSnapshotParticipant{{
				SenderID: 1,
				State:    "talking",
			}},
		}},
	}
	complete, channels, err = reassembly.add(first)
	if err != nil || !complete {
		t.Fatalf("complete snapshot result = complete:%v err:%v", complete, err)
	}
	state.applyRelayStateSnapshot(channels)
	if got := state.channels[100][1]; got != "talking" {
		t.Fatalf("channel 100 sender 1 state = %q", got)
	}
	if _, found := state.channels[101]; !found {
		t.Fatal("empty channel was not retained in the snapshot projection")
	}
	if got := state.snapshot()["channel_count"]; got != 2 {
		t.Fatalf("channel_count = %#v, want 2", got)
	}
}

func TestPrivateControlStateSnapshotReassemblyRejectsDuplicateChunk(t *testing.T) {
	reassembly := &privateControlSnapshotReassembly{
		snapshotID: "AAAAAAAAAAAAAAAAAAAAAA",
		chunkCount: 1,
		chunks:     make(map[uint16][]privateControlSnapshotChannel),
	}
	chunk := privateControlRelayStateSnapshot{
		SnapshotID: "AAAAAAAAAAAAAAAAAAAAAA",
		ChunkIndex: 0,
		ChunkCount: 1,
		Channels:   []privateControlSnapshotChannel{},
	}
	if _, _, err := reassembly.add(chunk); err != nil {
		t.Fatalf("first chunk: %v", err)
	}
	if _, _, err := reassembly.add(chunk); err == nil {
		t.Fatal("duplicate snapshot chunk was accepted")
	}
}

func TestManagementStateDoesNotRetainLifecycleEvents(t *testing.T) {
	state := &managementState{}
	state.markConnected("relay-test")
	state.recordLifecycleEvent(privateControlLifecycleEvent{EventType: "talk_started"})
	snapshot := state.snapshot()
	if snapshot["status"] != "connected" || snapshot["last_event_type"] != "talk_started" {
		t.Fatalf("unexpected state snapshot: %#v", snapshot)
	}
	state.markDisconnected()
	if state.snapshot()["status"] != "disconnected" {
		t.Fatal("state did not record disconnection")
	}
}

func TestPrivateControlUDSClientDoesNotRequireTLSMaterial(t *testing.T) {
	client, err := newPrivateControlClient(privateControlClientConfig{
		transport: privateControlTransportUDS, udsSocketPath: "/run/incomudon-pcl/relay.sock", serviceID: "management-main",
	}, &managementState{})
	if err != nil {
		t.Fatalf("new UDS client: %v", err)
	}
	if client.tlsConfig != nil {
		t.Fatal("UDS client unexpectedly configured TLS")
	}
	if _, err := newPrivateControlClient(privateControlClientConfig{
		transport: privateControlTransportUDS, udsSocketPath: "relative.sock", serviceID: "management-main",
	}, &managementState{}); err == nil {
		t.Fatal("UDS client accepted a relative socket path")
	}
}
