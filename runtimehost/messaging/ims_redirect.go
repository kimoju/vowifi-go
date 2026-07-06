package messaging

import (
	"strconv"
	"strings"
	"time"

	"github.com/boa-z/vowifi-go/runtimehost/voiceclient"
)

const maxIMSMessagingRedirects = 4

type imsMessagingResponseHandling struct {
	StatusCode                 int
	Reason                     string
	RetryAfter                 time.Duration
	RedirectURI                string
	AuthChallengeHeader        string
	AuthChallenge              string
	AuthAuthorizationHeader    string
	RegistrationRecoveryNeeded bool
	FailureText                string
}

func imsMessagingResponseHandlingFor(resp voiceclient.SIPResponse) imsMessagingResponseHandling {
	info := imsMessagingResponseHandling{
		StatusCode:                 resp.StatusCode,
		Reason:                     strings.TrimSpace(resp.Reason),
		RetryAfter:                 voiceclient.SIPResponseRetryAfter(resp),
		RedirectURI:                firstMessagingRedirectContactURI(resp),
		RegistrationRecoveryNeeded: IMSRegistrationRecoveryNeededStatus(resp.StatusCode),
	}
	info.AuthChallengeHeader, info.AuthAuthorizationHeader = imsMessagingAuthHeaders(resp.StatusCode)
	if info.AuthChallengeHeader != "" {
		info.AuthChallenge = firstHeaderValue(resp.Headers, info.AuthChallengeHeader)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		info.FailureText = firstNonEmpty(info.Reason, "IMS MESSAGE rejected: "+strconv.Itoa(resp.StatusCode))
	}
	return info
}

func imsMessagingAuthHeaders(statusCode int) (challengeHeader, authorizationHeader string) {
	switch statusCode {
	case 401:
		return "WWW-Authenticate", "Authorization"
	case 407:
		return "Proxy-Authenticate", "Proxy-Authorization"
	default:
		return "", ""
	}
}

func retryMessagingDialogConfigForRedirect(cfg voiceclient.DialogRequestConfig, resp voiceclient.SIPResponse, cseq int) (voiceclient.DialogRequestConfig, bool) {
	target := imsMessagingResponseHandlingFor(resp).RedirectURI
	if target == "" {
		return voiceclient.DialogRequestConfig{}, false
	}
	retryCfg := cfg
	retryCfg.RemoteTargetURI = target
	retryCfg.CSeq = cseq
	return retryCfg, true
}

func nextMessagingCSeq(cseq int) int {
	if cseq <= 0 {
		return 1
	}
	return cseq + 1
}

func firstMessagingRedirectContactURI(resp voiceclient.SIPResponse) string {
	if resp.StatusCode < 300 || resp.StatusCode >= 400 {
		return ""
	}
	for _, uri := range messagingRedirectContactURIs(resp.Headers) {
		return uri
	}
	return ""
}

func messagingRedirectContactURIs(headers map[string][]string) []string {
	var out []string
	for key, values := range headers {
		if !strings.EqualFold(key, "Contact") {
			continue
		}
		for _, value := range values {
			for _, contact := range splitUSSDHeaderValues(value) {
				uri := sipHeaderURIValue(contact)
				if !isMessagingRedirectTargetURI(uri) {
					continue
				}
				duplicate := false
				for _, existing := range out {
					if existing == uri {
						duplicate = true
						break
					}
				}
				if !duplicate {
					out = append(out, uri)
				}
			}
		}
	}
	return out
}

func isMessagingRedirectTargetURI(uri string) bool {
	uri = strings.TrimSpace(uri)
	if uri == "" || uri == "*" {
		return false
	}
	lower := strings.ToLower(uri)
	return strings.HasPrefix(lower, "sip:") || strings.HasPrefix(lower, "sips:")
}
