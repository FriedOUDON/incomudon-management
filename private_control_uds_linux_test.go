//go:build linux

package main

import (
	"context"
	"net"
	"path/filepath"
	"testing"
	"time"
)

func TestPrivateControlClientConsumesLifecycleEventOverUDS(t *testing.T) {
	socketPath := filepath.Join(t.TempDir(), "relay.sock")
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatalf("listen UDS: %v", err)
	}
	t.Cleanup(func() { _ = listener.Close() })

	serverDone := make(chan error, 1)
	go func() {
		connection, err := listener.Accept()
		if err != nil {
			serverDone <- err
			return
		}
		defer connection.Close()
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
		if hello.ManagementServiceID != "management-main" || hello.WantLifecycleEvents == nil || !*hello.WantLifecycleEvents || hello.WantAuditInputs == nil || *hello.WantAuditInputs || hello.WantDiagnostics == nil || *hello.WantDiagnostics {
			serverDone <- errUnexpectedPrivateControlHello
			return
		}
		if err := writePrivateControlFrame(connection, privateControlHelloAck{
			SchemaVersion:           privateControlSchemaVersion,
			Type:                    "hello_ack",
			MessageID:               "MDEyMzQ1Njc4OTo7PD0-Pw",
			InReplyTo:               hello.MessageID,
			SessionID:               "ERITFBUWFxgZGhscHR4fIA",
			RelayID:                 "relay-test",
			LifecycleEventsAccepted: boolPointer(true),
			AuditInputsAccepted:     boolPointer(false),
			DiagnosticsAccepted:     boolPointer(false),
		}); err != nil {
			serverDone <- err
			return
		}
		if err := writePrivateControlFrame(connection, privateControlLifecycleEvent{
			SchemaVersion: privateControlSchemaVersion,
			Type:          "relay_lifecycle_event",
			MessageID:     "ISIjJCUmJygpKissLS4vMA",
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
	client, err := newPrivateControlClient(privateControlClientConfig{
		transport: privateControlTransportUDS, udsSocketPath: socketPath, serviceID: "management-main",
		commandStoreFile: t.TempDir() + "/pcl-revocations.json",
	}, state)
	if err != nil {
		t.Fatalf("new UDS client: %v", err)
	}
	if err := client.runSession(context.Background()); err == nil {
		t.Fatal("UDS session unexpectedly ended without an error")
	}
	if err := <-serverDone; err != nil {
		t.Fatalf("test UDS Relay: %v", err)
	}
	if snapshot := state.snapshot(); snapshot["status"] != "connected" || snapshot["relay_id"] != "relay-test" || snapshot["last_event_type"] != "relay_health_changed" {
		t.Fatalf("unexpected UDS client state: %#v", snapshot)
	}
}
