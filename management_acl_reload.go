package main

import (
	"context"
	"fmt"
	"log"
	"sort"
	"strings"
	"time"
)

const managementAPIAutomaticRevocationDenyWindow = 90 * time.Minute

type managementAutomaticRevocationTarget struct {
	channelID uint32
	serviceID string
	reason    string
}

func parseManagementACLReloadInterval(value string) (time.Duration, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return 5 * time.Second, nil
	}
	interval, err := time.ParseDuration(value)
	if err != nil || interval < time.Second || interval > time.Minute {
		return 0, fmt.Errorf("Management API ACL reload interval must be from 1s through 1m")
	}
	return interval, nil
}

func (a *managementAPI) runAuthorizerReload(ctx context.Context) {
	if a == nil || a.aclReloadInterval == 0 {
		return
	}
	ticker := time.NewTicker(a.aclReloadInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			queued, err := a.reloadAuthorizer()
			if err != nil {
				log.Printf("Management API ACL reload rejected: %v", err)
				continue
			}
			if queued > 0 {
				log.Printf("Management API ACL reload durably queued %d Service Admission revocation(s)", queued)
			}
		}
	}
}

func (a *managementAPI) reloadAuthorizer() (int, error) {
	if a == nil {
		return 0, fmt.Errorf("Management API is unavailable")
	}
	replacement, err := loadManagementAPIAuthorizer(a.servicesFile, a.channelACLFile, a.globalPermissionsFile)
	if err != nil {
		return 0, err
	}
	a.authorizerMu.RLock()
	previous := a.authorizer
	a.authorizerMu.RUnlock()
	targets := managementAutomaticRevocations(previous, replacement)
	if len(targets) > 0 {
		queuer, ok := a.revoker.(interface {
			queueServiceAdmissionRevocations([]managementServiceAdmissionRevocationRequest) error
		})
		if !ok {
			return 0, fmt.Errorf("ACL reload requires a durable PCL revocation queue")
		}
		denyUntil := time.Now().Add(managementAPIAutomaticRevocationDenyWindow).Unix()
		requests := make([]managementServiceAdmissionRevocationRequest, 0, len(targets))
		for _, target := range targets {
			requests = append(requests, managementServiceAdmissionRevocationRequest{
				ChannelID: target.channelID,
				ServiceID: target.serviceID,
				Reason:    target.reason,
				DenyUntil: denyUntil,
			})
		}
		if err := queuer.queueServiceAdmissionRevocations(requests); err != nil {
			return 0, fmt.Errorf("durably queue ACL-triggered Service Admission revocations: %w", err)
		}
	}
	a.authorizerMu.Lock()
	a.authorizer = replacement
	a.authorizerMu.Unlock()
	return len(targets), nil
}

func managementAutomaticRevocations(previous, replacement managementAPIAuthorizer) []managementAutomaticRevocationTarget {
	targets := make(map[string]managementAutomaticRevocationTarget)
	for serviceID, oldService := range previous.byService {
		if oldService == nil || !oldService.enabled {
			continue
		}
		newService, serviceRemainsEnabled := replacement.byService[serviceID]
		serviceRemainsEnabled = serviceRemainsEnabled && newService != nil && newService.enabled
		for key, oldACL := range oldService.admissions {
			if !oldACL.enabled {
				continue
			}
			reason := ""
			if !serviceRemainsEnabled {
				reason = "service_disabled"
			} else if newACL, found := newService.admissions[key]; !found || !managementAdmissionACLEquivalent(oldACL, newACL) {
				reason = "acl_removed"
			}
			if reason == "" {
				continue
			}
			mapKey := fmt.Sprintf("%s/%d", serviceID, key.channelID)
			_, found := targets[mapKey]
			if !found || reason == "service_disabled" {
				targets[mapKey] = managementAutomaticRevocationTarget{channelID: key.channelID, serviceID: serviceID, reason: reason}
			}
		}
	}
	result := make([]managementAutomaticRevocationTarget, 0, len(targets))
	for _, target := range targets {
		result = append(result, target)
	}
	sort.Slice(result, func(left, right int) bool {
		if result[left].serviceID == result[right].serviceID {
			return result[left].channelID < result[right].channelID
		}
		return result[left].serviceID < result[right].serviceID
	})
	return result
}

func managementAdmissionACLEquivalent(left, right managementAdmissionACL) bool {
	return left.role == right.role &&
		left.allowListen == right.allowListen &&
		left.allowTalk == right.allowTalk &&
		left.allowInterrupt == right.allowInterrupt &&
		left.interruptPriority == right.interruptPriority &&
		left.enabled == right.enabled
}
