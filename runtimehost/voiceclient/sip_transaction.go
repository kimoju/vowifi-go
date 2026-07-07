package voiceclient

import (
	"strings"
	"time"
)

const (
	defaultSIPTimerT1 = 500 * time.Millisecond
	defaultSIPTimerT2 = 4 * time.Second
	defaultSIPTimerT4 = 5 * time.Second
)

// SIPTransactionTimerConfig overrides the RFC 3261 transaction timer base values.
type SIPTransactionTimerConfig struct {
	T1 time.Duration
	T2 time.Duration
	T4 time.Duration
}

// SIPTransactionTimerPolicy describes the client transaction timers for a request method.
type SIPTransactionTimerPolicy struct {
	Method string
	Invite bool
	T1     time.Duration
	T2     time.Duration
	T4     time.Duration
	TimerA time.Duration
	TimerB time.Duration
	TimerE time.Duration
	TimerF time.Duration
	TimerK time.Duration
}

// SIPTransactionRetrySchedule describes UDP retransmission timing before timeout.
type SIPTransactionRetrySchedule struct {
	Method      string
	Invite      bool
	Intervals   []time.Duration
	Timeout     time.Duration
	CleanupWait time.Duration
}

// DefaultSIPTransactionTimerPolicy returns the default transaction timer policy.
func DefaultSIPTransactionTimerPolicy(method string) SIPTransactionTimerPolicy {
	return SIPTransactionTimerPolicyFor(method, SIPTransactionTimerConfig{})
}

// SIPTransactionTimerPolicyFor returns transaction timers using cfg base values.
func SIPTransactionTimerPolicyFor(method string, cfg SIPTransactionTimerConfig) SIPTransactionTimerPolicy {
	method = strings.ToUpper(strings.TrimSpace(method))
	t1 := cfg.T1
	if t1 <= 0 {
		t1 = defaultSIPTimerT1
	}
	t2 := cfg.T2
	if t2 <= 0 {
		t2 = defaultSIPTimerT2
	}
	if t2 < t1 {
		t2 = t1
	}
	t4 := cfg.T4
	if t4 <= 0 {
		t4 = defaultSIPTimerT4
	}
	policy := SIPTransactionTimerPolicy{
		Method: method,
		Invite: sipTransactionKindForMethod(method) == sipTransactionInvite,
		T1:     t1,
		T2:     t2,
		T4:     t4,
	}
	if policy.Invite {
		policy.TimerA = t1
		policy.TimerB = 64 * t1
		return policy
	}
	policy.TimerE = t1
	policy.TimerF = 64 * t1
	policy.TimerK = t4
	return policy
}

// SIPTransactionRetryScheduleFor returns the retry schedule for a UDP client transaction.
func SIPTransactionRetryScheduleFor(method string, cfg SIPTransactionTimerConfig) SIPTransactionRetrySchedule {
	policy := SIPTransactionTimerPolicyFor(method, cfg)
	interval := policy.TimerE
	timeout := policy.TimerF
	cleanupWait := policy.TimerK
	if policy.Invite {
		interval = policy.TimerA
		timeout = policy.TimerB
		cleanupWait = 0
	}
	schedule := SIPTransactionRetrySchedule{
		Method:      policy.Method,
		Invite:      policy.Invite,
		Timeout:     timeout,
		CleanupWait: cleanupWait,
	}
	for elapsed := time.Duration(0); interval > 0 && elapsed+interval < timeout; {
		schedule.Intervals = append(schedule.Intervals, interval)
		elapsed += interval
		interval = nextSIPRetransmitInterval(interval, policy.T2)
	}
	return schedule
}
