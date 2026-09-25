package main

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestManagementLiveSSEStartsAfterSubscriptionAndFiltersChannels(t *testing.T) {
	state := newManagementState()
	hub := newManagementLiveEventHub()
	state.setLiveEvents(hub)
	api := &managementAPI{state: state, eventDelivery: managementAPIEventDeliveryLive, liveEvents: hub}
	service := &managementAPIService{apiRole: "viewer", channels: map[uint32]struct{}{100: {}}, globalPermissions: map[string]struct{}{}}

	// This event predates the subscription and must never be replayed.
	state.recordLifecycleEvent(testManagementLifecycleEvent(100, 1))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	request := httptest.NewRequest(http.MethodGet, "/v1/events", nil).WithContext(ctx)
	request.Header.Set("Last-Event-ID", "not-a-decimal-cursor")
	writer := newManagementSSETestWriter()
	done := make(chan struct{})
	go func() {
		api.handleEvents(writer, request, service)
		close(done)
	}()
	writer.waitForFlush(t)
	waitForManagementSSESubscriber(t, hub, 1)

	// Channel 200 is hidden. Its event ID still advances the shared cursor.
	state.recordLifecycleEvent(testManagementLifecycleEvent(200, 2))
	state.recordLifecycleEvent(testManagementLifecycleEvent(100, 3))
	writer.waitForFlush(t)
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("live SSE handler did not stop after request cancellation")
	}

	body := writer.bodyString()
	if writer.statusCode() != http.StatusOK || writer.Header().Get("Content-Type") != "text/event-stream" {
		t.Fatalf("live SSE response = status %d headers %#v", writer.statusCode(), writer.Header())
	}
	if strings.Contains(body, `"sender_id":1`) || strings.Contains(body, `"sender_id":2`) {
		t.Fatalf("live SSE replayed or leaked an unauthorized event: %q", body)
	}
	if !strings.Contains(body, "id: 3\nevent: talk_started\n") || !strings.Contains(body, `"sender_id":3`) {
		t.Fatalf("live SSE authorized event = %q", body)
	}
}

func TestManagementLiveSSERejectsSinceAndEnforcesOpenAuthorization(t *testing.T) {
	state := newManagementState()
	hub := newManagementLiveEventHub()
	state.setLiveEvents(hub)
	api := &managementAPI{state: state, eventDelivery: managementAPIEventDeliveryLive, liveEvents: hub}
	viewer := &managementAPIService{apiRole: "viewer", channels: map[uint32]struct{}{100: {}}, globalPermissions: map[string]struct{}{}}

	for _, rawQuery := range []string{"since=150", "since=not-a-cursor", "since"} {
		response := httptest.NewRecorder()
		api.handleEvents(response, httptest.NewRequest(http.MethodGet, "/v1/events?"+rawQuery, nil), viewer)
		if response.Code != http.StatusBadRequest {
			t.Fatalf("live SSE query %q status = %d", rawQuery, response.Code)
		}
	}

	unauthorized := &managementAPIService{apiRole: "admin", channels: map[uint32]struct{}{}, globalPermissions: map[string]struct{}{}}
	response := httptest.NewRecorder()
	api.handleEvents(response, httptest.NewRequest(http.MethodGet, "/v1/events", nil), unauthorized)
	if response.Code != http.StatusForbidden {
		t.Fatalf("unauthorized live SSE status = %d", response.Code)
	}

	auditor := &managementAPIService{apiRole: "auditor", channels: map[uint32]struct{}{100: {}}, globalPermissions: map[string]struct{}{}}
	if !auditor.canOpenEventStream() || !auditor.canReceiveEvent(managementEvent{ChannelID: uint32Pointer(100)}) || auditor.canReadChannel(100) {
		t.Fatal("auditor event scope was not isolated from viewer state scope")
	}
	healthOnly := &managementAPIService{apiRole: "auditor", channels: map[uint32]struct{}{}, globalPermissions: map[string]struct{}{managementAPIHealthPermission: {}}}
	if !healthOnly.canOpenEventStream() || !healthOnly.canReceiveEvent(managementEvent{Type: "relay_health_changed"}) || healthOnly.canReceiveEvent(managementEvent{ChannelID: uint32Pointer(100)}) {
		t.Fatal("global health event authorization is incorrect")
	}
}

func TestManagementLiveSSEBoundsSubscribers(t *testing.T) {
	hub := newManagementLiveEventHub()
	unsubscribers := make([]func(), 0, managementLiveEventMaximumSubscribers)
	for index := 0; index < managementLiveEventMaximumSubscribers; index++ {
		_, unsubscribe, subscribed := hub.subscribe()
		if !subscribed {
			t.Fatalf("subscriber %d was rejected before the configured limit", index)
		}
		unsubscribers = append(unsubscribers, unsubscribe)
	}
	if _, _, subscribed := hub.subscribe(); subscribed {
		t.Fatal("live SSE subscriber limit was not enforced")
	}
	for _, unsubscribe := range unsubscribers {
		unsubscribe()
	}
}

func testManagementLifecycleEvent(channelID, senderID uint32) privateControlLifecycleEvent {
	return privateControlLifecycleEvent{
		SchemaVersion: privateControlSchemaVersion,
		Type:          "relay_lifecycle_event",
		OccurredAt:    time.Now().UTC().Format(time.RFC3339),
		EventType:     "talk_started",
		ChannelID:     uint32Pointer(channelID),
		SenderID:      uint32Pointer(senderID),
	}
}

func uint32Pointer(value uint32) *uint32 {
	return &value
}

type managementSSETestWriter struct {
	header  http.Header
	mu      sync.Mutex
	status  int
	body    bytes.Buffer
	flushes chan struct{}
}

func newManagementSSETestWriter() *managementSSETestWriter {
	return &managementSSETestWriter{header: make(http.Header), flushes: make(chan struct{}, 4)}
}

func (w *managementSSETestWriter) Header() http.Header {
	return w.header
}

func (w *managementSSETestWriter) WriteHeader(status int) {
	w.mu.Lock()
	if w.status == 0 {
		w.status = status
	}
	w.mu.Unlock()
}

func (w *managementSSETestWriter) Write(data []byte) (int, error) {
	w.mu.Lock()
	if w.status == 0 {
		w.status = http.StatusOK
	}
	count, err := w.body.Write(data)
	w.mu.Unlock()
	return count, err
}

func (w *managementSSETestWriter) Flush() {
	select {
	case w.flushes <- struct{}{}:
	default:
	}
}

func (w *managementSSETestWriter) waitForFlush(t *testing.T) {
	t.Helper()
	select {
	case <-w.flushes:
	case <-time.After(time.Second):
		t.Fatal("live SSE handler did not flush")
	}
}

func (w *managementSSETestWriter) statusCode() int {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.status
}

func (w *managementSSETestWriter) bodyString() string {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.body.String()
}

func waitForManagementSSESubscriber(t *testing.T, hub *managementLiveEventHub, count int) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if hub.subscriberCount() == count {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("live SSE subscriber count = %d, want %d", hub.subscriberCount(), count)
}
