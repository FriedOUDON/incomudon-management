package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"sync"
)

const (
	managementLiveEventSubscriberBuffer   = 32
	managementLiveEventMaximumSubscribers = 128
)

type managementEvent struct {
	SchemaVersion  string  `json:"schema_version"`
	EventID        string  `json:"event_id"`
	OccurredAt     string  `json:"occurred_at"`
	Type           string  `json:"type"`
	ChannelID      *uint32 `json:"channel_id"`
	SenderID       *uint32 `json:"sender_id,omitempty"`
	ServiceID      *string `json:"service_id,omitempty"`
	RecordingJobID *string `json:"recording_job_id,omitempty"`
	State          *string `json:"state,omitempty"`
	Reason         *string `json:"reason,omitempty"`
}

type managementLiveEventHub struct {
	mu          sync.Mutex
	nextEventID uint64
	nextSubID   uint64
	subscribers map[uint64]chan managementEvent
}

func newManagementLiveEventHub() *managementLiveEventHub {
	return &managementLiveEventHub{subscribers: make(map[uint64]chan managementEvent)}
}

func (h *managementLiveEventHub) subscribe() (<-chan managementEvent, func(), bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if len(h.subscribers) >= managementLiveEventMaximumSubscribers {
		return nil, nil, false
	}
	h.nextSubID++
	id := h.nextSubID
	subscriber := make(chan managementEvent, managementLiveEventSubscriberBuffer)
	h.subscribers[id] = subscriber
	return subscriber, func() {
		h.unsubscribe(id)
	}, true
}

func (h *managementLiveEventHub) unsubscribe(id uint64) {
	h.mu.Lock()
	subscriber, found := h.subscribers[id]
	if found {
		delete(h.subscribers, id)
		close(subscriber)
	}
	h.mu.Unlock()
}

func (h *managementLiveEventHub) publish(input privateControlLifecycleEvent) {
	h.mu.Lock()
	if h.nextEventID == ^uint64(0) {
		h.mu.Unlock()
		return
	}
	h.nextEventID++
	event := managementEvent{
		SchemaVersion:  "management-event-v1",
		EventID:        strconv.FormatUint(h.nextEventID, 10),
		OccurredAt:     input.OccurredAt,
		Type:           input.EventType,
		ChannelID:      input.ChannelID,
		SenderID:       input.SenderID,
		ServiceID:      input.ServiceID,
		RecordingJobID: input.RecordingJobID,
		State:          input.State,
		Reason:         input.Reason,
	}
	for id, subscriber := range h.subscribers {
		select {
		case subscriber <- event:
		default:
			// A live-only client cannot retain or replay a stalled stream.
			delete(h.subscribers, id)
			close(subscriber)
		}
	}
	h.mu.Unlock()
}

func (h *managementLiveEventHub) subscriberCount() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return len(h.subscribers)
}

func (a *managementAPI) handleEvents(writer http.ResponseWriter, request *http.Request, service *managementAPIService) {
	if request.Method != http.MethodGet {
		writeManagementAPIMethodNotAllowed(writer, http.MethodGet)
		return
	}
	if a.eventDeliveryMode() != managementAPIEventDeliveryLive || a.liveEvents == nil {
		writeManagementAPIError(writer, http.StatusNotFound)
		return
	}
	if _, supplied := request.URL.Query()["since"]; supplied {
		writeManagementAPIError(writer, http.StatusBadRequest)
		return
	}
	if !service.canOpenEventStream() {
		writeManagementAPIError(writer, http.StatusForbidden)
		return
	}
	flusher, ok := writer.(http.Flusher)
	if !ok {
		writeManagementAPIError(writer, http.StatusInternalServerError)
		return
	}
	subscriber, unsubscribe, subscribed := a.liveEvents.subscribe()
	if !subscribed {
		writeManagementAPIError(writer, http.StatusServiceUnavailable)
		return
	}
	defer unsubscribe()
	writer.Header().Set("Content-Type", "text/event-stream")
	writer.Header().Set("Cache-Control", "no-cache")
	writer.Header().Set("Connection", "keep-alive")
	writer.Header().Set("X-Accel-Buffering", "no")
	fmt.Fprint(writer, ": connected\n\n")
	flusher.Flush()
	for {
		select {
		case <-request.Context().Done():
			return
		case event, open := <-subscriber:
			if !open {
				return
			}
			if !service.canReceiveEvent(event) {
				continue
			}
			if err := writeManagementSSEEvent(writer, event); err != nil {
				return
			}
			flusher.Flush()
		}
	}
}

func writeManagementSSEEvent(writer http.ResponseWriter, event managementEvent) error {
	data, err := json.Marshal(event)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(writer, "id: %s\nevent: %s\ndata: %s\n\n", event.EventID, event.Type, data)
	return err
}
