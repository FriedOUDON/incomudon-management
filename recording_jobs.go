package main

import (
	"errors"
	"net/http"
	"sync"
)

const managementRecordingJobLimit = 4096

var errManagementRecordingJobLimit = errors.New("recording job limit reached")

type managementRecordingJobRequest struct {
	ChannelID uint32 `json:"channel_id"`
}

type managementRecordingJobResponse struct {
	JobID string `json:"job_id"`
	State string `json:"state"`
}

type managementRecordingJob struct {
	jobID             string
	channelID         uint32
	recorderServiceID string
	state             string
}

type managementRecordingJobs struct {
	mu   sync.RWMutex
	jobs map[string]managementRecordingJob
}

func newManagementRecordingJobs() *managementRecordingJobs {
	return &managementRecordingJobs{jobs: make(map[string]managementRecordingJob)}
}

func (j *managementRecordingJobs) create(channelID uint32, recorderServiceID string) (managementRecordingJob, error) {
	if j == nil {
		return managementRecordingJob{}, errors.New("recording jobs are unavailable")
	}
	jobID, err := newPrivateControlID()
	if err != nil {
		return managementRecordingJob{}, err
	}
	job := managementRecordingJob{
		jobID:             jobID,
		channelID:         channelID,
		recorderServiceID: recorderServiceID,
		state:             "starting",
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	if len(j.jobs) >= managementRecordingJobLimit {
		return managementRecordingJob{}, errManagementRecordingJobLimit
	}
	j.jobs[jobID] = job
	return job, nil
}

func (j *managementRecordingJobs) stop(jobID string) (managementRecordingJob, bool) {
	if j == nil {
		return managementRecordingJob{}, false
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	job, found := j.jobs[jobID]
	if !found {
		return managementRecordingJob{}, false
	}
	if job.state != "stopped" && job.state != "failed" {
		job.state = "stopping"
		j.jobs[jobID] = job
	}
	return job, true
}

func (j *managementRecordingJobs) get(jobID string) (managementRecordingJob, bool) {
	if j == nil {
		return managementRecordingJob{}, false
	}
	j.mu.RLock()
	defer j.mu.RUnlock()
	job, found := j.jobs[jobID]
	return job, found
}

func (j *managementRecordingJobs) applyLifecycleEvent(event privateControlLifecycleEvent) {
	if j == nil || event.EventType != "recording_state_changed" || event.RecordingJobID == nil || event.ChannelID == nil || event.State == nil {
		return
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	job, found := j.jobs[*event.RecordingJobID]
	if !found || job.channelID != *event.ChannelID {
		return
	}
	job.state = *event.State
	j.jobs[job.jobID] = job
}

func (s *managementAPIService) canManageRecordingChannel(channelID uint32) bool {
	if s == nil || (s.apiRole != "recorder" && s.apiRole != "operator") {
		return false
	}
	_, found := s.channels[channelID]
	return found
}

func (a *managementAPI) handleRecordingJobStart(writer http.ResponseWriter, request *http.Request, service *managementAPIService) {
	if request.Method != http.MethodPost {
		writeManagementAPIMethodNotAllowed(writer, http.MethodPost)
		return
	}
	var body managementRecordingJobRequest
	if err := decodeManagementAPIRequest(writer, request, &body); err != nil {
		writeManagementAPIError(writer, http.StatusBadRequest)
		return
	}
	if !service.canManageRecordingChannel(body.ChannelID) {
		writeManagementAPIError(writer, http.StatusForbidden)
		return
	}
	job, err := a.recordingJobs.create(body.ChannelID, service.serviceID)
	if err != nil {
		writeManagementAPIError(writer, http.StatusServiceUnavailable)
		return
	}
	writer.Header().Set("Cache-Control", "no-store")
	writeJSON(writer, http.StatusCreated, managementRecordingJobResponse{JobID: job.jobID, State: job.state})
}

func (a *managementAPI) handleRecordingJobStop(writer http.ResponseWriter, request *http.Request, service *managementAPIService, jobID string) {
	if request.Method != http.MethodPost {
		writeManagementAPIMethodNotAllowed(writer, http.MethodPost)
		return
	}
	job, found := a.recordingJobs.get(jobID)
	if !found || !service.canManageRecordingChannel(job.channelID) {
		// Do not disclose whether an opaque job ID exists outside the caller's scope.
		writeManagementAPIError(writer, http.StatusForbidden)
		return
	}
	a.recordingJobs.stop(jobID)
	writer.Header().Set("Cache-Control", "no-store")
	writer.WriteHeader(http.StatusAccepted)
}
