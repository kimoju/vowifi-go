package messaging

import (
	"sort"
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
	type redirectContact struct {
		uri string
		q   float64
	}

	var contacts []redirectContact
	for key, values := range headers {
		if !strings.EqualFold(key, "Contact") {
			continue
		}
		for _, value := range values {
			for _, contact := range splitUSSDHeaderValues(value) {
				uri := sipHeaderURIValue(contact)
				if !isMessagingRedirectTargetURI(uri) || messagingRedirectContactExpired(contact) {
					continue
				}
				q := messagingRedirectContactQ(contact)
				duplicate := -1
				for i, existing := range contacts {
					if existing.uri == uri {
						duplicate = i
						break
					}
				}
				if duplicate >= 0 {
					if q > contacts[duplicate].q {
						contacts[duplicate].q = q
					}
					continue
				}
				contacts = append(contacts, redirectContact{uri: uri, q: q})
			}
		}
	}
	sort.SliceStable(contacts, func(i, j int) bool {
		return contacts[i].q > contacts[j].q
	})
	out := make([]string, 0, len(contacts))
	for _, contact := range contacts {
		out = append(out, contact.uri)
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

func messagingRedirectContactQ(contact string) float64 {
	value, ok := sipContactHeaderParam(contact, "q")
	if !ok {
		return 1
	}
	q, err := strconv.ParseFloat(value, 64)
	if err != nil || q < 0 || q > 1 {
		return 1
	}
	return q
}

func messagingRedirectContactExpired(contact string) bool {
	value, ok := sipContactHeaderParam(contact, "expires")
	if !ok {
		return false
	}
	expires, err := strconv.Atoi(value)
	return err == nil && expires <= 0
}

func sipContactHeaderParam(contact, name string) (string, bool) {
	for _, param := range sipContactHeaderParams(contact) {
		key, raw, ok := strings.Cut(strings.TrimSpace(param), "=")
		if !ok || !strings.EqualFold(strings.TrimSpace(key), name) {
			continue
		}
		return strings.Trim(strings.TrimSpace(raw), `"`), true
	}
	return "", false
}

func sipContactHeaderParams(contact string) []string {
	var out []string
	var cur strings.Builder
	inQuote := false
	escaped := false
	angleDepth := 0
	collecting := false
	for _, r := range contact {
		switch {
		case escaped:
			if collecting {
				cur.WriteRune(r)
			}
			escaped = false
		case r == '\\' && inQuote:
			if collecting {
				cur.WriteRune(r)
			}
			escaped = true
		case r == '"':
			if collecting {
				cur.WriteRune(r)
			}
			inQuote = !inQuote
		case r == '<' && !inQuote:
			if collecting {
				cur.WriteRune(r)
			}
			angleDepth++
		case r == '>' && !inQuote:
			if collecting {
				cur.WriteRune(r)
			}
			if angleDepth > 0 {
				angleDepth--
			}
		case r == ';' && !inQuote && angleDepth == 0:
			if collecting {
				if part := strings.TrimSpace(cur.String()); part != "" {
					out = append(out, part)
				}
				cur.Reset()
			}
			collecting = true
		default:
			if collecting {
				cur.WriteRune(r)
			}
		}
	}
	if collecting {
		if part := strings.TrimSpace(cur.String()); part != "" {
			out = append(out, part)
		}
	}
	return out
}
