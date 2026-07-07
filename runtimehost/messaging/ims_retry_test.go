package messaging

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/boa-z/vowifi-go/runtimehost/voiceclient"
)

type imsRetryTimeoutError struct{}

func (imsRetryTimeoutError) Error() string   { return "timeout" }
func (imsRetryTimeoutError) Timeout() bool   { return true }
func (imsRetryTimeoutError) Temporary() bool { return true }

func TestPlanIMSSMSSubmitRetryAcceptedIsTerminalAndDurable(t *testing.T) {
	now := time.Date(2026, 7, 7, 10, 0, 0, 0, time.UTC)
	plan := PlanIMSSMSSubmitRetry(
		SMSSendRequest{
			MessageID: "billing July",
			Peer:      "+18005551212",
			Part:      SMSPart{PartNo: 2},
		},
		SMSSendResult{SIPCode: 202, State: "accepted"},
		nil,
		IMSMessagingRetryOptions{Attempt: 1, Now: now},
	)

	if plan.Operation != IMSMessagingRetryOperationSMSSubmit ||
		plan.Method != "MESSAGE" ||
		plan.Class != IMSMessagingRetryClassAccepted ||
		plan.Action != IMSMessagingRetryActionNone ||
		plan.Retry ||
		!plan.Terminal ||
		plan.RetryKey != "sms-submit:billing-July:part-2" ||
		plan.IdempotencyKey != plan.RetryKey ||
		plan.Durable {
		t.Fatalf("accepted SMS retry plan=%+v", plan)
	}
	if !plan.NextAttemptAt.IsZero() || plan.Delay != 0 {
		t.Fatalf("accepted plan scheduled retry: %+v", plan)
	}
	if _, err := json.Marshal(plan); err != nil {
		t.Fatalf("Marshal retry plan error = %v", err)
	}
}

func TestPlanIMSMessagingRetryClassifies4xxAndRetryAfter(t *testing.T) {
	now := time.Date(2026, 7, 7, 10, 0, 0, 0, time.UTC)
	plan := PlanIMSMessagingRetry(IMSMessagingRetryInput{
		Operation: IMSMessagingRetryOperationSMSSubmit,
		Method:    "MESSAGE",
		Response: voiceclient.SIPResponse{
			StatusCode: 429,
			Reason:     "Too Many Requests",
			Headers:    map[string][]string{"Retry-After": {"0"}},
		},
		Attempt:        2,
		Now:            now,
		IdempotencyKey: "sms-submit:rate-limited:part-1",
	})

	if plan.Class != IMSMessagingRetryClassThrottled ||
		!plan.Retry ||
		plan.Terminal ||
		plan.Action != IMSMessagingRetryActionRetryAfter ||
		!plan.RetryAfterPresent ||
		plan.RetryAfter != 0 ||
		plan.Delay != 0 ||
		!plan.NextAttemptAt.Equal(now) ||
		!plan.Durable {
		t.Fatalf("429 retry plan=%+v", plan)
	}

	forbidden := PlanIMSMessagingRetry(IMSMessagingRetryInput{
		Operation:      IMSMessagingRetryOperationSMSSubmit,
		Method:         "MESSAGE",
		Response:       voiceclient.SIPResponse{StatusCode: 403, Reason: "Forbidden"},
		Attempt:        1,
		IdempotencyKey: "sms-submit:forbidden:part-1",
	})
	if forbidden.Class != IMSMessagingRetryClassClientFailure ||
		forbidden.Retry ||
		!forbidden.Terminal ||
		forbidden.Action != IMSMessagingRetryActionNone ||
		forbidden.Reason != "Forbidden" {
		t.Fatalf("403 retry plan=%+v", forbidden)
	}
}

func TestPlanIMSMessagingRetryClassifies5xxWithRetryAfter(t *testing.T) {
	now := time.Date(2026, 7, 7, 10, 0, 0, 0, time.UTC)
	plan := PlanIMSMessagingRetry(IMSMessagingRetryInput{
		Operation: IMSMessagingRetryOperationSMSSubmit,
		Method:    "MESSAGE",
		Response: voiceclient.SIPResponse{
			StatusCode: 503,
			Reason:     "Service Unavailable",
			Headers:    map[string][]string{"Retry-After": {"7"}},
		},
		Attempt:        1,
		Now:            now,
		IdempotencyKey: "sms-submit:server-failure:part-1",
	})

	if plan.Class != IMSMessagingRetryClassServerFailure ||
		!plan.Retry ||
		plan.Action != IMSMessagingRetryActionRecoverRegistration ||
		!plan.RegistrationRecoveryNeeded ||
		!plan.TargetFailover ||
		!plan.RetryAfterPresent ||
		plan.RetryAfter != 7*time.Second ||
		plan.Delay != 7*time.Second ||
		!plan.NextAttemptAt.Equal(now.Add(7*time.Second)) ||
		!plan.Durable {
		t.Fatalf("503 retry plan=%+v", plan)
	}
}

func TestPlanIMSSMSSubmitRetryClassifiesSIPTimeoutWithBackoff(t *testing.T) {
	now := time.Date(2026, 7, 7, 10, 0, 0, 0, time.UTC)
	plan := PlanIMSSMSSubmitRetry(
		SMSSendRequest{
			MessageID: "timeout sms",
			Peer:      "+18005551212",
			Part:      SMSPart{PartNo: 1},
		},
		SMSSendResult{},
		imsRetryTimeoutError{},
		IMSMessagingRetryOptions{
			Attempt: 3,
			Now:     now,
			Policy: IMSMessagingRetryPolicy{
				MaxAttempts: 5,
				BaseDelay:   2 * time.Second,
				MaxDelay:    9 * time.Second,
			},
		},
	)

	if plan.Class != IMSMessagingRetryClassSIPTimeout ||
		!plan.TransportFailure ||
		!plan.TimedOut ||
		!plan.Retry ||
		plan.Action != IMSMessagingRetryActionRecoverRegistration ||
		!plan.RegistrationRecoveryNeeded ||
		!plan.DuplicateRisk ||
		plan.Delay != 8*time.Second ||
		plan.NextAttempt != 4 ||
		!plan.NextAttemptAt.Equal(now.Add(8*time.Second)) ||
		plan.RetryKey != "sms-submit:timeout-sms:part-1" ||
		!plan.Durable {
		t.Fatalf("timeout SMS retry plan=%+v", plan)
	}
}

func TestPlanIMSUSSDSessionRetryUsesSessionKeyAndStopsAtAttemptLimit(t *testing.T) {
	req := USSDRequest{SessionID: "ussd menu", Input: "1"}
	plan := PlanIMSUSSDSessionRetry(
		req,
		USSDResult{SessionID: req.SessionID, Status: 408, Done: true},
		errors.New("SIP timeout"),
		IMSMessagingRetryOptions{
			Attempt: 4,
			Policy:  IMSMessagingRetryPolicy{MaxAttempts: 4, BaseDelay: time.Second, MaxDelay: 8 * time.Second},
		},
	)

	if plan.Operation != IMSMessagingRetryOperationUSSDSession ||
		plan.Method != "INFO" ||
		plan.Class != IMSMessagingRetryClassSIPTimeout ||
		!plan.TimedOut ||
		plan.Retry ||
		!plan.Terminal ||
		plan.Action != IMSMessagingRetryActionNone ||
		plan.SessionKey != "ussd-session:ussd-menu" ||
		plan.RetryKey != plan.SessionKey ||
		plan.Durable ||
		plan.Delay != 0 {
		t.Fatalf("USSD attempt-limit plan=%+v", plan)
	}
}

func TestPlanIMSUSSDSessionRetryRedirectsToTarget(t *testing.T) {
	now := time.Date(2026, 7, 7, 10, 0, 0, 0, time.UTC)
	plan := PlanIMSMessagingRetry(IMSMessagingRetryInput{
		Operation: IMSMessagingRetryOperationUSSDSession,
		Method:    "INVITE",
		Response: voiceclient.SIPResponse{
			StatusCode: 302,
			Reason:     "Moved Temporarily",
			Headers:    map[string][]string{"Contact": {"<sip:ussd-backup@ims.example>;q=0.8"}},
		},
		Attempt:    1,
		Now:        now,
		SessionKey: "ussd-session:menu",
	})

	if plan.Class != IMSMessagingRetryClassRedirect ||
		!plan.Retry ||
		plan.Action != IMSMessagingRetryActionFailoverTarget ||
		plan.TargetURI != "sip:ussd-backup@ims.example" ||
		!plan.TargetFailover ||
		plan.Delay != time.Second ||
		!plan.NextAttemptAt.Equal(now.Add(time.Second)) ||
		!plan.Durable {
		t.Fatalf("USSD redirect retry plan=%+v", plan)
	}
}

func TestPlanIMSMessagingRetryDoesNotRetryCallerCancellation(t *testing.T) {
	plan := PlanIMSMessagingRetry(IMSMessagingRetryInput{
		Operation:      IMSMessagingRetryOperationSMSSubmit,
		Method:         "MESSAGE",
		Err:            context.Canceled,
		Attempt:        1,
		IdempotencyKey: "sms-submit:canceled:part-1",
	})

	if plan.Class != IMSMessagingRetryClassTransportFailure ||
		!plan.TransportFailure ||
		plan.Retry ||
		!plan.Terminal ||
		plan.Action != IMSMessagingRetryActionNone ||
		plan.Durable {
		t.Fatalf("canceled retry plan=%+v", plan)
	}
}

func TestIMSMessagingRetryKeysAreStable(t *testing.T) {
	smsKey := IMSMessagingSMSSubmitIdempotencyKey(SMSSendRequest{
		Peer: "+18005551212",
		Part: SMSPart{},
	})
	if smsKey != "sms-submit:18005551212:part-1" {
		t.Fatalf("SMS idempotency key=%q", smsKey)
	}
	ussdKey := IMSMessagingUSSDSessionKey(USSDRequest{Command: "*100#"})
	if ussdKey != "ussd-session:100" {
		t.Fatalf("USSD session key=%q", ussdKey)
	}
}
