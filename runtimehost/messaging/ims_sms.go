package messaging

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/kimoju/vowifi-go/runtimehost/voiceclient"
)

type IMSSMSTransport struct {
	Transport            voiceclient.SIPRequestTransport
	Profile              voiceclient.IMSProfile
	Registration         voiceclient.RegistrationBinding
	Domain               string
	LocalURI             string
	ContactURI           string
	RemoteTargetURI      string
	UserAgent            string
	ContentType          string
	SMSC                 string
	SMSCRPAddress        string
	UseCPIM              bool
	IMDNNotifications    []string
	DisableStatusReports bool
}

var (
	imsDeliveryReportCallCounter atomic.Uint64
	imsSMSMessageRefCounter      atomic.Uint32
)

func nextIMSSMSMessageRef() byte {
	return byte(imsSMSMessageRefCounter.Add(1) & 0xff)
}

func randomSIPTag(prefix string) string {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		if prefix == "" {
			return strconv.FormatInt(time.Now().UnixNano(), 16)
		}
		return fmt.Sprintf("%s-%x", prefix, time.Now().UnixNano())
	}
	if prefix == "" {
		return hex.EncodeToString(b[:])
	}
	return prefix + "-" + hex.EncodeToString(b[:])
}

func (t IMSSMSTransport) SendIMSDeliveryReport(ctx context.Context, req IMSDeliveryReportRequest) (IMSDeliveryReportResult, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if t.Transport == nil {
		return IMSDeliveryReportResult{}, ErrSMSTransportUnavailable
	}
	localURI := firstNonEmpty(req.LocalURI, t.LocalURI, t.Registration.PublicIdentity, t.Profile.IMPU)
	remoteURI := strings.TrimSpace(req.RemoteURI)
	if localURI == "" || remoteURI == "" || len(req.Body) == 0 {
		return IMSDeliveryReportResult{}, errors.New("IMS SMS delivery report is incomplete")
	}
	cfg := voiceclient.DialogRequestConfig{
		Profile:         t.Profile,
		Registration:    t.Registration,
		LocalURI:        localURI,
		ContactURI:      firstNonEmpty(t.ContactURI, t.Registration.ContactURI),
		RemoteURI:       remoteURI,
		RemoteTargetURI: firstNonEmpty(req.RemoteTargetURI, remoteURI),
		CallID:          fmt.Sprintf("sms-report-%d-%d@vowifi-go", time.Now().UnixNano(), imsDeliveryReportCallCounter.Add(1)),
		LocalTag:        randomSIPTag("sms-report"),
		CSeq:            1,
		UserAgent:       firstNonEmpty(t.UserAgent, t.Profile.UserAgent, "vowifi-go"),
	}
	contentType := firstNonEmpty(req.ContentType, IMS3GPPSMSContentType)
	msg, err := voiceclient.BuildMessageRequest(cfg, contentType, req.Body)
	if err != nil {
		return IMSDeliveryReportResult{}, err
	}
	if inReplyTo := strings.TrimSpace(req.InReplyTo); inReplyTo != "" {
		msg.Headers["In-Reply-To"] = inReplyTo
	}
	msg.Headers["Request-Disposition"] = "no-fork"
	if normalizedIMSMessageContentType(contentType) == IMS3GPPSMSContentType {
		msg.Headers["Content-Transfer-Encoding"] = "binary"
	}
	resp, err := voiceclient.RoundTripRequestWithDigestAuth(ctx, t.Transport, msg)
	handling := imsMessagingResponseHandlingFor(resp)
	result := IMSDeliveryReportResult{
		SIPCode:                    handling.StatusCode,
		RetryAfter:                 handling.RetryAfter,
		RegistrationRecoveryNeeded: handling.RegistrationRecoveryNeeded,
	}
	if err != nil {
		result.RegistrationRecoveryNeeded = !errors.Is(err, context.Canceled)
		return result, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return result, errors.New(handling.FailureText)
	}
	return result, nil
}

func (t IMSSMSTransport) SendSMSPart(ctx context.Context, req SMSSendRequest) (SMSSendResult, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if t.Transport == nil {
		return SMSSendResult{State: "failed", ErrorText: ErrSMSTransportUnavailable.Error()}, ErrSMSTransportUnavailable
	}
	peerURI := t.remoteURI(req.Peer)
	if peerURI == "" {
		err := errors.New("sms peer is empty")
		return SMSSendResult{State: "failed", ErrorText: err.Error()}, err
	}
	remoteURI := peerURI
	configuredContentType := firstNonEmpty(t.ContentType, IMS3GPPSMSContentType)
	if !strings.HasPrefix(strings.ToLower(configuredContentType), "text/plain") {
		if smscURI := t.remoteURI(t.SMSC); smscURI != "" {
			remoteURI = smscURI
		}
	}
	localURI := firstNonEmpty(t.LocalURI, t.Registration.PublicIdentity, t.Profile.IMPU)
	if localURI == "" {
		err := errors.New("IMS SMS local identity is empty")
		return SMSSendResult{State: "failed", ErrorText: err.Error()}, err
	}
	callID := smsCallID(req)
	cseq := req.Part.PartNo
	if cseq <= 0 {
		cseq = 1
	}
	var rpMR byte
	if req.Part.HasTPMR || req.Part.TPMR > 0 {
		rpMR = byte(req.Part.TPMR & 0xff)
	} else {
		rpMR = nextIMSSMSMessageRef()
	}
	contentType, body, err := t.messagePayload(req, rpMR, localURI, peerURI, callID)
	if err != nil {
		return SMSSendResult{CallID: callID, RPMR: int(rpMR), State: "failed", ErrorText: err.Error()}, err
	}
	cfg := voiceclient.DialogRequestConfig{
		Profile:         t.Profile,
		Registration:    t.Registration,
		LocalURI:        localURI,
		ContactURI:      firstNonEmpty(t.ContactURI, t.Registration.ContactURI),
		RemoteURI:       remoteURI,
		RemoteTargetURI: firstNonEmpty(t.RemoteTargetURI, remoteURI),
		CallID:          callID,
		LocalTag:        randomSIPTag("sms"),
		CSeq:            cseq,
		UserAgent:       firstNonEmpty(t.UserAgent, t.Profile.UserAgent, "vowifi-go"),
	}
	var resp voiceclient.SIPResponse
	redirectRetries := 0
	for {
		msg, err := voiceclient.BuildMessageRequest(cfg, contentType, body)
		if err != nil {
			return SMSSendResult{State: "failed", ErrorText: err.Error()}, err
		}
		msg.Headers["Request-Disposition"] = "no-fork"
		if normalizedIMSMessageContentType(contentType) == IMS3GPPSMSContentType {
			msg.Headers["Content-Transfer-Encoding"] = "binary"
		}
		resp, err = voiceclient.RoundTripRequestWithDigestAuth(ctx, t.Transport, msg)
		if err != nil {
			handling := imsMessagingResponseHandlingFor(resp)
			result := SMSSendResult{
				CallID:     callID,
				RPMR:       int(rpMR),
				SIPCode:    resp.StatusCode,
				RetryAfter: handling.RetryAfter,
				Headers:    resp.Headers,
			}
			result.State = "failed"
			result.ErrorText = err.Error()
			result.RegistrationRecoveryNeeded = !errors.Is(err, context.Canceled)
			return result, err
		}
		if redirectRetries < maxIMSMessagingRedirects {
			if retryCfg, ok := retryMessagingDialogConfigForRedirect(cfg, resp, nextMessagingCSeq(cfg.CSeq)); ok {
				cfg = retryCfg
				redirectRetries++
				continue
			}
		}
		break
	}
	handling := imsMessagingResponseHandlingFor(resp)
	result := SMSSendResult{
		CallID:     callID,
		RPMR:       int(rpMR),
		SIPCode:    handling.StatusCode,
		RetryAfter: handling.RetryAfter,
		Headers:    resp.Headers,
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		result.State = "failed"
		result.ErrorText = handling.FailureText
		result.RegistrationRecoveryNeeded = handling.RegistrationRecoveryNeeded
		return result, errors.New(result.ErrorText)
	}
	result.State = "sent"
	if resp.StatusCode == 202 {
		result.State = "accepted"
	}
	return result, nil
}

func IMSRegistrationRecoveryNeededStatus(code int) bool {
	switch code {
	case 408, 430, 480, 481, 500, 502, 503, 504, 580:
		return true
	default:
		return code >= 500 && code < 600
	}
}

func (t IMSSMSTransport) messagePayload(req SMSSendRequest, rpMR byte, localURI, remoteURI, messageID string) (string, []byte, error) {
	contentType := firstNonEmpty(t.ContentType, IMS3GPPSMSContentType)
	if strings.HasPrefix(strings.ToLower(contentType), "text/plain") {
		return contentType, []byte(req.Part.Text), nil
	}
	part := req.Part
	if !t.DisableStatusReports {
		part.RequestStatusReport = true
	}
	tpdu, err := BuildSMSSubmitTPDU(req.Peer, part, rpMR)
	if err != nil {
		return "", nil, err
	}
	rpSMSC, err := t.resolveRPDestinationAddress()
	if err != nil {
		return "", nil, err
	}
	rpData, err := BuildSMSRPData(rpMR, rpSMSC, tpdu)
	if err != nil {
		return "", nil, err
	}
	if t.UseCPIM {
		messageHeaders := BuildIMSCPIMIMDNMessageHeaders(localURI, remoteURI, messageID, t.imdnNotifications())
		contentHeaders := map[string][]string{"Content-Type": {contentType}}
		if normalizedIMSMessageContentType(contentType) == IMS3GPPSMSContentType {
			contentHeaders["Content-Transfer-Encoding"] = []string{"binary"}
		}
		cpim, err := BuildIMSCPIMMessageWithHeaders(messageHeaders, contentHeaders, rpData)
		if err != nil {
			return "", nil, err
		}
		return IMSCPIMContentType, cpim, nil
	}
	return contentType, rpData, nil
}

func (t IMSSMSTransport) resolveRPDestinationAddress() (string, error) {
	if explicit := strings.TrimSpace(t.SMSCRPAddress); explicit != "" {
		if _, err := encodeRPAddress(explicit); err != nil {
			return "", fmt.Errorf("invalid SMSC RP-DA address %q: %w", explicit, err)
		}
		return explicit, nil
	}
	if smsc := strings.TrimSpace(t.SMSC); smsc != "" {
		if encoded, err := encodeRPAddress(smsc); err == nil && len(encoded) >= 2 {
			return smsc, nil
		}
	}
	// Per 3GPP TS 24.011 §7.3.1.2 / §8.2.5.2 and TS 24.341 §5.3.1.2, MO RP-DATA
	// must include a non-empty BCD RP-Destination-Address (2..11 octets). When
	// the SMSC is configured only as a SIP PSI URI or unset, encode dummy +0000000.
	return "+0000000", nil
}

func (t IMSSMSTransport) imdnNotifications() []string {
	if len(t.IMDNNotifications) > 0 {
		return NormalizeIMSIMDNDispositionNotifications(t.IMDNNotifications...)
	}
	if t.DisableStatusReports {
		return nil
	}
	return []string{IMSIMDNDispositionPositiveDelivery, IMSIMDNDispositionNegativeDelivery}
}

func (t IMSSMSTransport) remoteURI(peer string) string {
	peer = strings.TrimSpace(peer)
	if peer == "" {
		return ""
	}
	lower := strings.ToLower(peer)
	if strings.HasPrefix(lower, "sip:") || strings.HasPrefix(lower, "sips:") || strings.HasPrefix(lower, "tel:") {
		return peer
	}
	if strings.Contains(peer, "@") {
		return "sip:" + peer
	}
	domain := firstNonEmpty(t.Domain, t.Profile.Domain, smsDomainFromURI(t.Registration.PublicIdentity), smsDomainFromURI(t.Profile.IMPU))
	if domain == "" {
		return "tel:" + peer
	}
	return "sip:" + peer + "@" + domain
}

func smsCallID(req SMSSendRequest) string {
	id := smsToken(firstNonEmpty(req.MessageID, "sms"))
	partNo := req.Part.PartNo
	if partNo <= 0 {
		partNo = 1
	}
	return id + "-" + strconv.Itoa(partNo) + "@vowifi-go"
}

func smsToken(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return "sms"
	}
	var b strings.Builder
	lastDash := false
	for _, r := range value {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '.', r == '_', r == '-':
			b.WriteRune(r)
			lastDash = false
		default:
			if !lastDash {
				b.WriteByte('-')
				lastDash = true
			}
		}
	}
	out := strings.Trim(b.String(), "-")
	if out == "" {
		return "sms"
	}
	return out
}

func smsDomainFromURI(uri string) string {
	uri = strings.TrimSpace(uri)
	if strings.HasPrefix(strings.ToLower(uri), "sip:") {
		uri = uri[4:]
	}
	if _, host, ok := strings.Cut(uri, "@"); ok {
		if semi := strings.IndexByte(host, ';'); semi >= 0 {
			host = host[:semi]
		}
		return strings.Trim(strings.TrimSpace(host), "<>")
	}
	return ""
}
