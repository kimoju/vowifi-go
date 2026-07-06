package messaging

import (
	"strings"

	"github.com/iniwex5/vowifi-go/runtimehost/voiceclient"
)

const maxIMSMessagingRedirects = 4

func retryMessagingDialogConfigForRedirect(cfg voiceclient.DialogRequestConfig, resp voiceclient.SIPResponse, cseq int) (voiceclient.DialogRequestConfig, bool) {
	target := firstMessagingRedirectContactURI(resp)
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
