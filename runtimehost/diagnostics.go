package runtimehost

import (
	"regexp"
	"strings"
	"time"

	"github.com/boa-z/vowifi-go/internal/tracefixture"
)

var runtimeLocalPathRE = regexp.MustCompile(`(?i)(?:/(?:home|Users)/[A-Za-z0-9_.-]+(?:/[^\s"'<>:;,)]*)*|[A-Za-z]:\\Users\\[A-Za-z0-9_.-]+(?:\\[^\s"'<>:;,)]*)*)`)

// DiagnosticState is a redacted runtime state view intended for logs, UI state,
// and support diagnostics. It preserves operational state while removing common
// subscriber identifiers, AKA/digest material, IPs, MACs, and local paths.
type DiagnosticState struct {
	DeviceID                 string
	Phase                    Phase
	DataplaneMode            string
	SIMReady                 bool
	AccessReady              bool
	TunnelReady              bool
	IMSReady                 bool
	SMSReady                 bool
	RegStatus                int
	RegStatusText            string
	NetworkMode              string
	LastErrorClass           string
	LastError                string
	LastReason               string
	IMSRecoveryPending       bool
	IMSRecoveryRetryAfter    time.Duration
	IMSRecoveryNextAttemptAt time.Time
	IMSRecoveryReason        string
	UpdatedAt                time.Time
	Redacted                 bool
}

// DiagnosticIMSRegisterResponseDecision is a redacted view of an IMS REGISTER
// recovery decision. It is suitable for logs/UI because it carries the
// operational recovery action without exposing SIP identities or auth material
// from the response reason.
type DiagnosticIMSRegisterResponseDecision struct {
	StatusCode      int
	Action          string
	Recoverable     bool
	Retry           bool
	Reauthenticate  bool
	RefreshIdentity bool
	RefreshSecurity bool
	Backoff         bool
	RetryAfter      time.Duration
	Reason          string
	Redacted        bool
}

// SafeDiagnosticState returns a diagnostic view of state with sensitive text
// fields redacted. It does not mutate the input State.
func SafeDiagnosticState(state State) DiagnosticState {
	redactor := tracefixture.NewRedactor()
	return DiagnosticState{
		DeviceID:                 redactRuntimeDiagnosticString(redactor, state.DeviceID),
		Phase:                    state.Phase,
		DataplaneMode:            redactRuntimeDiagnosticString(redactor, state.DataplaneMode),
		SIMReady:                 state.SIMReady,
		AccessReady:              state.AccessReady,
		TunnelReady:              state.TunnelReady,
		IMSReady:                 state.IMSReady,
		SMSReady:                 state.SMSReady,
		RegStatus:                state.RegStatus,
		RegStatusText:            redactRuntimeDiagnosticString(redactor, state.RegStatusText),
		NetworkMode:              redactRuntimeDiagnosticString(redactor, state.NetworkMode),
		LastErrorClass:           redactRuntimeDiagnosticString(redactor, state.LastErrorClass),
		LastError:                redactRuntimeDiagnosticString(redactor, state.LastError),
		LastReason:               redactRuntimeDiagnosticString(redactor, state.LastReason),
		IMSRecoveryPending:       state.IMSRecoveryPending,
		IMSRecoveryRetryAfter:    state.IMSRecoveryRetryAfter,
		IMSRecoveryNextAttemptAt: state.IMSRecoveryNextAttemptAt,
		IMSRecoveryReason:        redactRuntimeDiagnosticString(redactor, state.IMSRecoveryReason),
		UpdatedAt:                state.UpdatedAt,
		Redacted:                 true,
	}
}

// SafeDiagnosticIMSRegisterResponseDecision returns a diagnostic view of an IMS
// REGISTER recovery decision with optional response reason text redacted.
func SafeDiagnosticIMSRegisterResponseDecision(decision IMSRegisterResponseDecision, reason string) DiagnosticIMSRegisterResponseDecision {
	redactor := tracefixture.NewRedactor()
	return DiagnosticIMSRegisterResponseDecision{
		StatusCode:      decision.StatusCode,
		Action:          redactRuntimeDiagnosticString(redactor, decision.Action),
		Recoverable:     decision.Recoverable,
		Retry:           decision.Retry,
		Reauthenticate:  decision.Reauthenticate,
		RefreshIdentity: decision.RefreshIdentity,
		RefreshSecurity: decision.RefreshSecurity,
		Backoff:         decision.Backoff,
		RetryAfter:      decision.RetryAfter,
		Reason:          redactRuntimeDiagnosticString(redactor, reason),
		Redacted:        true,
	}
}

func redactRuntimeDiagnosticString(redactor *tracefixture.Redactor, value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	if redactor == nil {
		redactor = tracefixture.NewRedactor()
	}
	value = redactor.RedactString(value)
	return runtimeLocalPathRE.ReplaceAllString(value, "<redacted-local-path>")
}
