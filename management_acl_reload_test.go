package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestManagementAutomaticRevocationsDetectACLRemovalAndServiceDisablement(t *testing.T) {
	oldACL := managementAdmissionACL{role: "recorder", allowListen: true, enabled: true}
	previous := managementAPIAuthorizer{byService: map[string]*managementAPIService{
		"recorder-01": {
			serviceID: "recorder-01",
			enabled:   true,
			admissions: map[managementAdmissionKey]managementAdmissionACL{
				{channelID: 100, senderID: 9001}: oldACL,
				{channelID: 200, senderID: 9002}: oldACL,
			},
		},
	}}
	replacement := managementAPIAuthorizer{byService: map[string]*managementAPIService{
		"recorder-01": {
			serviceID: "recorder-01",
			enabled:   true,
			admissions: map[managementAdmissionKey]managementAdmissionACL{
				{channelID: 200, senderID: 9002}: oldACL,
			},
		},
	}}
	targets := managementAutomaticRevocations(previous, replacement)
	if len(targets) != 1 || targets[0] != (managementAutomaticRevocationTarget{channelID: 100, serviceID: "recorder-01", reason: "acl_removed"}) {
		t.Fatalf("ACL removal targets = %#v", targets)
	}
	replacement.byService["recorder-01"].enabled = false
	targets = managementAutomaticRevocations(previous, replacement)
	if len(targets) != 2 {
		t.Fatalf("service disablement targets = %#v", targets)
	}
	for _, target := range targets {
		if target.serviceID != "recorder-01" || target.reason != "service_disabled" {
			t.Fatalf("service disablement target = %#v", target)
		}
	}
}

func TestManagementAPIReloadQueuesBeforeReplacingAuthorizer(t *testing.T) {
	directory := t.TempDir()
	services := filepath.Join(directory, "management-services.csv")
	acls := filepath.Join(directory, "management-channel-acl.csv")
	permissions := filepath.Join(directory, "management-global-permissions.csv")
	writeManagementACLFiles(t, services, acls, permissions, true)
	previous, err := loadManagementAPIAuthorizer(services, acls, permissions)
	if err != nil {
		t.Fatal(err)
	}
	store, pending, err := openPrivateControlCommandStore(filepath.Join(directory, "pcl-revocations.json"), testNow())
	if err != nil {
		t.Fatal(err)
	}
	client := &privateControlClient{pending: pending, commandStore: store, commandNotify: make(chan struct{}, 1)}
	api := &managementAPI{
		authorizer:            previous,
		servicesFile:          services,
		channelACLFile:        acls,
		globalPermissionsFile: permissions,
		revoker:               client,
	}
	writeManagementACLFiles(t, services, acls, permissions, false)
	queued, err := api.reloadAuthorizer()
	if err != nil || queued != 1 {
		t.Fatalf("reload = %d, %v", queued, err)
	}
	if len(client.pending) != 1 {
		t.Fatalf("pending PCL commands = %#v", client.pending)
	}
	if len(api.authorizer.byService["recorder-01"].admissions) != 0 {
		t.Fatal("replacement ACL was not installed after durable queueing")
	}
}

func TestManagementAPIReloadKeepsPreviousAuthorizerWhenQueueUnavailable(t *testing.T) {
	directory := t.TempDir()
	services := filepath.Join(directory, "management-services.csv")
	acls := filepath.Join(directory, "management-channel-acl.csv")
	permissions := filepath.Join(directory, "management-global-permissions.csv")
	writeManagementACLFiles(t, services, acls, permissions, true)
	previous, err := loadManagementAPIAuthorizer(services, acls, permissions)
	if err != nil {
		t.Fatal(err)
	}
	api := &managementAPI{
		authorizer:            previous,
		servicesFile:          services,
		channelACLFile:        acls,
		globalPermissionsFile: permissions,
		revoker:               &fakeManagementServiceAdmissionRevoker{},
	}
	writeManagementACLFiles(t, services, acls, permissions, false)
	if _, err := api.reloadAuthorizer(); err == nil {
		t.Fatal("reload unexpectedly succeeded without a durable PCL queue")
	}
	if len(api.authorizer.byService["recorder-01"].admissions) != 1 {
		t.Fatal("previous ACL was replaced despite failed revocation queue")
	}
}

func TestParseManagementACLReloadInterval(t *testing.T) {
	interval, err := parseManagementACLReloadInterval("")
	if err != nil || interval.String() != "5s" {
		t.Fatalf("default reload interval = %s, %v", interval, err)
	}
	if _, err := parseManagementACLReloadInterval("500ms"); err == nil {
		t.Fatal("sub-second reload interval was accepted")
	}
}

func writeManagementACLFiles(t *testing.T, services, acls, permissions string, includeAdmission bool) {
	t.Helper()
	write := func(filename, value string) {
		if err := os.WriteFile(filename, []byte(value), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write(services, "service_id,certificate_sha256,api_role,enabled\nrecorder-01,aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa,recorder,true\n")
	rows := "service_id,channel_id,sender_id,admission_role,allow_listen,allow_talk,allow_interrupt,interrupt_priority,enabled\n"
	if includeAdmission {
		rows += "recorder-01,100,9001,recorder,true,false,false,0,true\n"
	}
	write(acls, rows)
	write(permissions, "service_id,permission,enabled\n")
}

func testNow() time.Time { return time.Now() }
