package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"
)

const (
	managementServiceAdmissionCommandWait       = 5 * time.Second
	managementServiceAdmissionMaximumDenyWindow = 90 * time.Minute
)

type managementServiceAdmissionGrantRequest struct {
	ChannelID        uint32 `json:"channel_id"`
	SenderID         uint32 `json:"sender_id"`
	Role             string `json:"role"`
	RequestTalk      bool   `json:"request_talk"`
	RequestInterrupt bool   `json:"request_interrupt"`
	ServicePublicKey string `json:"service_public_key"`
}

type managementServiceAdmissionGrantResponse struct {
	Grant     string `json:"grant"`
	ExpiresAt string `json:"expires_at"`
}

type managementServiceAdmissionRevocationRequest struct {
	ChannelID   uint32 `json:"channel_id"`
	ServiceID   string `json:"service_id,omitempty"`
	GrantIDHash string `json:"grant_id_hash,omitempty"`
	Reason      string `json:"reason"`
	DenyUntil   int64  `json:"deny_until"`
}

type managementServiceAdmissionRevocationResponse struct {
	Outcome                 string `json:"outcome"`
	DenyUntil               int64  `json:"deny_until"`
	AffectedMembershipCount uint32 `json:"affected_membership_count"`
	TalkReleaseCount        uint32 `json:"talk_release_count"`
}

type managementServiceAdmissionRevocationPendingResponse struct {
	Status    string `json:"status"`
	MessageID string `json:"message_id"`
	DenyUntil int64  `json:"deny_until"`
}

func (a *managementAPI) handleServiceAdmissionGrant(writer http.ResponseWriter, request *http.Request, service *managementAPIService) {
	if request.Method != http.MethodPost {
		writeManagementAPIMethodNotAllowed(writer, http.MethodPost)
		return
	}
	if a.issuer == nil {
		writeManagementAPIError(writer, http.StatusServiceUnavailable)
		return
	}
	if service.apiRole != "recorder" && service.apiRole != "operator" {
		writeManagementAPIError(writer, http.StatusForbidden)
		return
	}
	var body managementServiceAdmissionGrantRequest
	if err := decodeManagementAPIRequest(writer, request, &body); err != nil {
		writeManagementAPIError(writer, http.StatusBadRequest)
		return
	}
	acl, allowed := service.admissionACL(body.ChannelID, body.SenderID)
	if !allowed {
		writeManagementAPIError(writer, http.StatusForbidden)
		return
	}
	grant, expiresAt, err := a.issuer.issue(service.serviceID, acl, body, time.Now())
	if err != nil {
		if errors.Is(err, errServiceAdmissionGrantTracking) {
			writeManagementAPIError(writer, http.StatusServiceUnavailable)
			return
		}
		writeManagementAPIError(writer, http.StatusBadRequest)
		return
	}
	writer.Header().Set("Cache-Control", "no-store")
	writeJSON(writer, http.StatusCreated, managementServiceAdmissionGrantResponse{
		Grant:     grant,
		ExpiresAt: expiresAt.Format(time.RFC3339),
	})
}

func (a *managementAPI) handleServiceAdmissionRevocation(writer http.ResponseWriter, request *http.Request, service *managementAPIService) {
	if request.Method != http.MethodPost {
		writeManagementAPIMethodNotAllowed(writer, http.MethodPost)
		return
	}
	if service.apiRole != "admin" || !service.hasGlobalPermission(managementAPIRevokePermission) {
		writeManagementAPIError(writer, http.StatusForbidden)
		return
	}
	var body managementServiceAdmissionRevocationRequest
	if err := decodeManagementAPIRequest(writer, request, &body); err != nil {
		writeManagementAPIError(writer, http.StatusBadRequest)
		return
	}
	if err := a.validateServiceAdmissionRevocation(body); err != nil {
		writeManagementAPIError(writer, http.StatusBadRequest)
		return
	}
	if a.revoker == nil {
		writeManagementAPIError(writer, http.StatusServiceUnavailable)
		return
	}
	commandContext, cancel := context.WithTimeout(request.Context(), managementServiceAdmissionCommandWait)
	defer cancel()
	ack, messageID, err := a.revoker.revokeServiceAdmission(commandContext, body)
	if err == nil {
		if ack.DenyUntil != body.DenyUntil {
			writeManagementAPIError(writer, http.StatusServiceUnavailable)
			return
		}
		writeJSON(writer, http.StatusOK, managementServiceAdmissionRevocationResponse{
			Outcome:                 ack.Outcome,
			DenyUntil:               ack.DenyUntil,
			AffectedMembershipCount: ack.AffectedMembershipCount,
			TalkReleaseCount:        ack.TalkReleaseCount,
		})
		return
	}
	if errors.Is(err, context.DeadlineExceeded) && messageID != "" {
		writeJSON(writer, http.StatusAccepted, managementServiceAdmissionRevocationPendingResponse{
			Status:    "pending_relay_ack",
			MessageID: messageID,
			DenyUntil: body.DenyUntil,
		})
		return
	}
	writeManagementAPIError(writer, http.StatusServiceUnavailable)
}

func (a *managementAPI) validateServiceAdmissionRevocation(request managementServiceAdmissionRevocationRequest) error {
	now := time.Now().Unix()
	if !validServiceAdmissionRevocationReason(request.Reason) || request.DenyUntil <= now ||
		request.DenyUntil > now+int64(managementServiceAdmissionMaximumDenyWindow/time.Second) ||
		(request.ServiceID == "" && request.GrantIDHash == "") {
		return fmt.Errorf("invalid Service Admission revocation request")
	}
	if request.ServiceID != "" && !validManagementServiceID(request.ServiceID) {
		return fmt.Errorf("invalid service_id")
	}
	if request.GrantIDHash == "" {
		return nil
	}
	if !validPrivateControlGrantIDHash(request.GrantIDHash) || a.issuer == nil {
		return fmt.Errorf("unknown grant_id_hash")
	}
	grant, found := a.issuer.issuedGrant(request.GrantIDHash, time.Now())
	if !found || grant.channelID != request.ChannelID || (request.ServiceID != "" && request.ServiceID != grant.serviceID) || request.DenyUntil > grant.expiresAt.Unix() {
		return fmt.Errorf("grant-specific revocation is outside the issued grant scope")
	}
	return nil
}

func validServiceAdmissionRevocationReason(value string) bool {
	switch value {
	case "acl_removed", "service_disabled", "grant_revoked":
		return true
	default:
		return false
	}
}

func decodeManagementAPIRequest(writer http.ResponseWriter, request *http.Request, target any) error {
	decoder := json.NewDecoder(http.MaxBytesReader(writer, request.Body, 4096))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return fmt.Errorf("request body must contain one JSON object")
	}
	return nil
}
