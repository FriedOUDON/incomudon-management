package main

import (
	"testing"
	"time"
)

func TestPrivateControlCommandStoreRestoresAndCompletesPendingRevocation(t *testing.T) {
	filename := t.TempDir() + "/pcl-revocations.json"
	store, pending, err := openPrivateControlCommandStore(filename, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	client := &privateControlClient{
		pending:       pending,
		commandStore:  store,
		commandNotify: make(chan struct{}, 1),
	}
	messageID, err := client.queueServiceAdmissionRevocation(managementServiceAdmissionRevocationRequest{
		ChannelID: 100,
		ServiceID: "recorder-01",
		Reason:    "service_disabled",
		DenyUntil: time.Now().Add(time.Minute).Unix(),
	})
	if err != nil {
		t.Fatal(err)
	}
	store, restored, err := openPrivateControlCommandStore(filename, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if len(restored) != 1 || restored[messageID] == nil {
		t.Fatalf("restored pending commands = %#v", restored)
	}
	restarted := &privateControlClient{pending: restored, commandStore: store, commandNotify: make(chan struct{}, 1)}
	completed, err := restarted.completePendingAcknowledgement(privateControlAck{
		InReplyTo: messageID,
		DenyUntil: restored[messageID].message.DenyUntil,
	})
	if err != nil || !completed {
		t.Fatalf("complete restored command = %t, %v", completed, err)
	}
	_, restored, err = openPrivateControlCommandStore(filename, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if len(restored) != 0 {
		t.Fatalf("persisted commands after acknowledgement = %#v", restored)
	}
}
