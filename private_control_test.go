package main

import (
	"bytes"
	"encoding/binary"
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
	if !validPrivateControlLifecycleEvent(event) {
		t.Fatal("valid lifecycle event was rejected")
	}
	event.EventType = "invalid-event"
	if validPrivateControlLifecycleEvent(event) {
		t.Fatal("invalid lifecycle event name was accepted")
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
