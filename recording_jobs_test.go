package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestManagementAPIRecordingJobsAreACLBound(t *testing.T) {
	jobs := newManagementRecordingJobs()
	api := &managementAPI{recordingJobs: jobs}
	recorder := &managementAPIService{
		serviceID: "recorder-01", apiRole: "recorder", channels: map[uint32]struct{}{100: {}},
	}
	startBody, err := json.Marshal(managementRecordingJobRequest{ChannelID: 100})
	if err != nil {
		t.Fatal(err)
	}
	startResponse := httptest.NewRecorder()
	api.handleRecordingJobStart(startResponse, httptest.NewRequest(http.MethodPost, "/v1/recording-jobs", bytes.NewReader(startBody)), recorder)
	if startResponse.Code != http.StatusCreated || startResponse.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("start response = status %d headers %#v", startResponse.Code, startResponse.Header())
	}
	var created managementRecordingJobResponse
	if err := json.NewDecoder(startResponse.Result().Body).Decode(&created); err != nil {
		t.Fatal(err)
	}
	if !validPrivateControlID(created.JobID) || created.State != "starting" {
		t.Fatalf("created job = %#v", created)
	}
	job, found := jobs.get(created.JobID)
	if !found || job.channelID != 100 || job.recorderServiceID != recorder.serviceID || job.state != "starting" {
		t.Fatalf("stored job = %#v found=%t", job, found)
	}

	forbiddenStart := httptest.NewRecorder()
	api.handleRecordingJobStart(forbiddenStart, httptest.NewRequest(http.MethodPost, "/v1/recording-jobs", bytes.NewReader([]byte(`{"channel_id":200}`))), recorder)
	if forbiddenStart.Code != http.StatusForbidden {
		t.Fatalf("out-of-scope start status = %d", forbiddenStart.Code)
	}

	otherRecorder := &managementAPIService{
		serviceID: "recorder-02", apiRole: "recorder", channels: map[uint32]struct{}{200: {}},
	}
	forbiddenStop := httptest.NewRecorder()
	api.handleRecordingJobStop(forbiddenStop, httptest.NewRequest(http.MethodPost, "/v1/recording-jobs/"+created.JobID+"/stop", nil), otherRecorder, created.JobID)
	if forbiddenStop.Code != http.StatusForbidden {
		t.Fatalf("out-of-scope stop status = %d", forbiddenStop.Code)
	}
	job, _ = jobs.get(created.JobID)
	if job.state != "starting" {
		t.Fatalf("unauthorized stop changed job state to %q", job.state)
	}

	stopResponse := httptest.NewRecorder()
	api.handleRecordingJobStop(stopResponse, httptest.NewRequest(http.MethodPost, "/v1/recording-jobs/"+created.JobID+"/stop", nil), recorder, created.JobID)
	if stopResponse.Code != http.StatusAccepted || stopResponse.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("stop response = status %d headers %#v", stopResponse.Code, stopResponse.Header())
	}
	job, _ = jobs.get(created.JobID)
	if job.state != "stopping" {
		t.Fatalf("stopped job state = %q", job.state)
	}
}

func TestManagementRecordingJobStateFollowsMatchingLifecycleEvent(t *testing.T) {
	jobs := newManagementRecordingJobs()
	job, err := jobs.create(100, "recorder-01")
	if err != nil {
		t.Fatal(err)
	}
	state := newManagementState()
	state.setRecordingJobs(jobs)
	channelID := uint32(100)
	recording := "recording"
	state.recordLifecycleEvent(privateControlLifecycleEvent{
		EventType: "recording_state_changed", ChannelID: &channelID, RecordingJobID: &job.jobID, State: &recording,
	})
	updated, found := jobs.get(job.jobID)
	if !found || updated.state != "recording" {
		t.Fatalf("updated job = %#v found=%t", updated, found)
	}

	wrongChannel := uint32(200)
	failed := "failed"
	state.recordLifecycleEvent(privateControlLifecycleEvent{
		EventType: "recording_state_changed", ChannelID: &wrongChannel, RecordingJobID: &job.jobID, State: &failed,
	})
	updated, _ = jobs.get(job.jobID)
	if updated.state != "recording" {
		t.Fatalf("mismatched lifecycle event changed job state to %q", updated.state)
	}
}

func TestManagementAPIRecordingJobStopPath(t *testing.T) {
	jobID := "example-job"
	if got, ok := managementAPIRecordingJobIDFromStopPath("/v1/recording-jobs/" + jobID + "/stop"); !ok || got != jobID {
		t.Fatalf("valid path = %q, %t", got, ok)
	}
	for _, path := range []string{
		"/v1/recording-jobs//stop",
		"/v1/recording-jobs/too/many/segments/stop",
		"/v1/recording-jobs/" + jobID,
		"/v1/recording-jobs/" + jobID + "/stop/extra",
	} {
		if _, ok := managementAPIRecordingJobIDFromStopPath(path); ok {
			t.Fatalf("invalid path accepted: %q", path)
		}
	}
}
