package voiceclient

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
)

var ErrInvalidDialogConfig = errors.New("invalid IMS dialog config")

const (
	imsMMTelService        = "urn:urn-7:3gpp-service.ims.icsi.mmtel"
	imsMMTelContactFeature = `+g.3gpp.icsi-ref="urn%3Aurn-7%3A3gpp-service.ims.icsi.mmtel"`
	imsMMTelAcceptContact  = "*;" + imsMMTelContactFeature
)

type SIPRequestMessage struct {
	Method      string
	URI         string
	Headers     map[string]string
	Body        []byte
	AuthSession *DigestAuthSession
}

type SIPIncomingRequest struct {
	Method  string
	URI     string
	Headers map[string][]string
	Body    []byte
}

type DialogRequestConfig struct {
	Profile          IMSProfile
	Registration     RegistrationBinding
	ContactURI       string
	LocalURI         string
	RemoteURI        string
	RemoteTargetURI  string
	CallID           string
	LocalTag         string
	RemoteTag        string
	CSeq             int
	RouteSet         []string
	UserAgent        string
	SessionExpires   int
	SessionRefresher string
	MinSE            int
	AuthHeader       string
	AuthHeaderName   string
	AuthSession      *DigestAuthSession
}

func BuildInviteRequest(cfg DialogRequestConfig, sdp []byte) (SIPRequestMessage, error) {
	msg, err := buildDialogRequest("INVITE", cfg, sdp)
	if err != nil {
		return SIPRequestMessage{}, err
	}
	if len(sdp) > 0 {
		msg.Headers["Content-Type"] = "application/sdp"
		msg.Headers["Accept"] = "application/sdp"
	}
	msg.Headers["P-Preferred-Service"] = imsMMTelService
	msg.Headers["Accept-Contact"] = imsMMTelAcceptContact
	msg.Headers["Supported"] = "100rel, timer, replaces, outbound"
	applySessionIntervalHeaders(msg.Headers, cfg)
	if cfg.MinSE > 0 {
		msg.Headers["Min-SE"] = strconv.Itoa(cfg.MinSE)
	}
	return msg, nil
}

func BuildAckRequest(cfg DialogRequestConfig) (SIPRequestMessage, error) {
	return buildDialogRequest("ACK", cfg, nil)
}

func BuildByeRequest(cfg DialogRequestConfig) (SIPRequestMessage, error) {
	return buildDialogRequest("BYE", cfg, nil)
}

func BuildByeRequestWithBody(cfg DialogRequestConfig, contentType string, body []byte) (SIPRequestMessage, error) {
	msg, err := buildDialogRequest("BYE", cfg, body)
	if err != nil {
		return SIPRequestMessage{}, err
	}
	if len(body) > 0 {
		msg.Headers["Content-Type"] = firstNonEmpty(contentType, "application/octet-stream")
	}
	return msg, nil
}

func BuildCancelRequest(cfg DialogRequestConfig) (SIPRequestMessage, error) {
	return BuildCancelRequestWithBody(cfg, "", nil)
}

func BuildCancelRequestWithBody(cfg DialogRequestConfig, contentType string, body []byte) (SIPRequestMessage, error) {
	msg, err := buildDialogRequest("CANCEL", cfg, body)
	if err != nil {
		return SIPRequestMessage{}, err
	}
	if len(body) > 0 {
		msg.Headers["Content-Type"] = firstNonEmpty(contentType, "application/octet-stream")
	}
	return msg, nil
}

func BuildUpdateRequest(cfg DialogRequestConfig, sdp []byte) (SIPRequestMessage, error) {
	msg, err := buildDialogRequest("UPDATE", cfg, sdp)
	if err != nil {
		return SIPRequestMessage{}, err
	}
	msg.Headers["Supported"] = "timer, replaces, outbound"
	applySessionIntervalHeaders(msg.Headers, cfg)
	if cfg.MinSE > 0 {
		msg.Headers["Min-SE"] = strconv.Itoa(cfg.MinSE)
	}
	if len(sdp) > 0 {
		msg.Headers["Content-Type"] = "application/sdp"
		msg.Headers["Accept"] = "application/sdp"
	}
	return msg, nil
}

func BuildPrackRequest(cfg DialogRequestConfig, rack string) (SIPRequestMessage, error) {
	return BuildPrackRequestWithBody(cfg, rack, "", nil)
}

func BuildPrackRequestWithBody(cfg DialogRequestConfig, rack, contentType string, body []byte) (SIPRequestMessage, error) {
	msg, err := buildDialogRequest("PRACK", cfg, body)
	if err != nil {
		return SIPRequestMessage{}, err
	}
	if strings.TrimSpace(rack) != "" {
		msg.Headers["RAck"] = strings.TrimSpace(rack)
	}
	if len(body) > 0 {
		msg.Headers["Content-Type"] = firstNonEmpty(contentType, "application/sdp")
	}
	return msg, nil
}

func BuildInfoRequest(cfg DialogRequestConfig, contentType string, body []byte) (SIPRequestMessage, error) {
	msg, err := buildDialogRequest("INFO", cfg, body)
	if err != nil {
		return SIPRequestMessage{}, err
	}
	if len(body) > 0 {
		msg.Headers["Content-Type"] = firstNonEmpty(contentType, "application/octet-stream")
	}
	if contactURI := firstNonEmpty(cfg.ContactURI, cfg.Registration.ContactURI); contactURI != "" {
		msg.Headers["Contact"] = "<" + contactURI + ">"
	}
	return msg, nil
}

func BuildMessageRequest(cfg DialogRequestConfig, contentType string, body []byte) (SIPRequestMessage, error) {
	msg, err := buildDialogRequest("MESSAGE", cfg, body)
	if err != nil {
		return SIPRequestMessage{}, err
	}
	if len(body) > 0 {
		msg.Headers["Content-Type"] = firstNonEmpty(contentType, "text/plain;charset=UTF-8")
	}
	msg.Headers["Accept"] = "text/plain, application/vnd.3gpp.sms"
	msg.Headers["P-Preferred-Service"] = "urn:urn-7:3gpp-service.ims.icsi.sms"
	msg.Headers["Accept-Contact"] = "*;+g.3gpp.smsip"
	if contactURI := firstNonEmpty(cfg.ContactURI, cfg.Registration.ContactURI); contactURI != "" {
		msg.Headers["Contact"] = "<" + contactURI + ">"
	}
	return msg, nil
}

func BuildReferRequest(cfg DialogRequestConfig, referTo, referredBy string) (SIPRequestMessage, error) {
	referTo = strings.TrimSpace(referTo)
	if referTo == "" {
		return SIPRequestMessage{}, fmt.Errorf("%w: Refer-To is empty", ErrInvalidDialogConfig)
	}
	msg, err := buildDialogRequest("REFER", cfg, nil)
	if err != nil {
		return SIPRequestMessage{}, err
	}
	msg.Headers["Refer-To"] = formatReferHeader(referTo)
	if referredBy = strings.TrimSpace(referredBy); referredBy != "" {
		msg.Headers["Referred-By"] = formatReferHeader(referredBy)
	}
	msg.Headers["Refer-Sub"] = "false"
	msg.Headers["Supported"] = "replaces, norefersub, outbound"
	return msg, nil
}

func BuildNotifyRequest(cfg DialogRequestConfig, event, subscriptionState, contentType string, body []byte) (SIPRequestMessage, error) {
	event = strings.TrimSpace(event)
	if event == "" {
		return SIPRequestMessage{}, fmt.Errorf("%w: Event is empty", ErrInvalidDialogConfig)
	}
	subscriptionState = strings.TrimSpace(subscriptionState)
	if subscriptionState == "" {
		return SIPRequestMessage{}, fmt.Errorf("%w: Subscription-State is empty", ErrInvalidDialogConfig)
	}
	msg, err := buildDialogRequest("NOTIFY", cfg, body)
	if err != nil {
		return SIPRequestMessage{}, err
	}
	msg.Headers["Event"] = event
	msg.Headers["Subscription-State"] = subscriptionState
	msg.Headers["Allow-Events"] = "refer"
	if len(body) > 0 {
		msg.Headers["Content-Type"] = firstNonEmpty(contentType, "message/sipfrag")
	}
	return msg, nil
}

func BuildSubscribeRequest(cfg DialogRequestConfig, event, expires, contentType string, body []byte) (SIPRequestMessage, error) {
	event = strings.TrimSpace(event)
	if event == "" {
		return SIPRequestMessage{}, fmt.Errorf("%w: Event is empty", ErrInvalidDialogConfig)
	}
	msg, err := buildDialogRequest("SUBSCRIBE", cfg, body)
	if err != nil {
		return SIPRequestMessage{}, err
	}
	msg.Headers["Event"] = event
	msg.Headers["Accept"] = "message/sipfrag"
	msg.Headers["Allow-Events"] = "refer"
	if expires = strings.TrimSpace(expires); expires != "" {
		msg.Headers["Expires"] = expires
	}
	if len(body) > 0 {
		msg.Headers["Content-Type"] = firstNonEmpty(contentType, "application/octet-stream")
	}
	return msg, nil
}

func BuildOptionsRequest(cfg DialogRequestConfig) (SIPRequestMessage, error) {
	msg, err := buildDialogRequest("OPTIONS", cfg, nil)
	if err != nil {
		return SIPRequestMessage{}, err
	}
	msg.Headers["Accept"] = "application/sdp"
	msg.Headers["Supported"] = "100rel, timer, replaces, outbound"
	return msg, nil
}

func buildDialogRequest(method string, cfg DialogRequestConfig, body []byte) (SIPRequestMessage, error) {
	method = strings.ToUpper(strings.TrimSpace(method))
	if method == "" {
		return SIPRequestMessage{}, fmt.Errorf("%w: method is empty", ErrInvalidDialogConfig)
	}
	localURI := firstNonEmpty(cfg.LocalURI, cfg.Registration.PublicIdentity, cfg.Profile.IMPU)
	remoteURI := strings.TrimSpace(cfg.RemoteURI)
	targetURI := firstNonEmpty(cfg.RemoteTargetURI, remoteURI)
	contactURI := firstNonEmpty(cfg.ContactURI, cfg.Registration.ContactURI)
	callID := strings.TrimSpace(cfg.CallID)
	if localURI == "" {
		return SIPRequestMessage{}, fmt.Errorf("%w: local URI is empty", ErrInvalidDialogConfig)
	}
	if remoteURI == "" {
		return SIPRequestMessage{}, fmt.Errorf("%w: remote URI is empty", ErrInvalidDialogConfig)
	}
	if targetURI == "" {
		return SIPRequestMessage{}, fmt.Errorf("%w: request URI is empty", ErrInvalidDialogConfig)
	}
	if contactURI == "" && method == "INVITE" {
		return SIPRequestMessage{}, fmt.Errorf("%w: contact URI is empty", ErrInvalidDialogConfig)
	}
	if callID == "" {
		return SIPRequestMessage{}, fmt.Errorf("%w: Call-ID is empty", ErrInvalidDialogConfig)
	}
	cseq := cfg.CSeq
	if cseq <= 0 {
		cseq = 1
	}
	localTag := firstNonEmpty(cfg.LocalTag, "vowifi-go")
	headers := map[string]string{
		"To":                    formatNameAddr(remoteURI, cfg.RemoteTag),
		"From":                  formatNameAddr(localURI, localTag),
		"Call-ID":               callID,
		"CSeq":                  strconv.Itoa(cseq) + " " + method,
		"Max-Forwards":          "70",
		"User-Agent":            firstNonEmpty(cfg.UserAgent, cfg.Profile.UserAgent, "vowifi-go"),
		"Allow":                 "INVITE, ACK, CANCEL, BYE, PRACK, UPDATE, INFO, MESSAGE, REFER, NOTIFY, SUBSCRIBE, OPTIONS",
		"P-Preferred-Identity":  "<" + localURI + ">",
		"P-Access-Network-Info": "IEEE-802.11",
	}
	if contactURI != "" && (method == "INVITE" || method == "UPDATE" || method == "INFO" || method == "NOTIFY" || method == "SUBSCRIBE") {
		headers["Contact"] = "<" + contactURI + ">"
	}
	if route := routeHeader(firstNonEmptySlice(cfg.RouteSet, cfg.Registration.ServiceRoutes)); route != "" {
		headers["Route"] = route
	}
	if securityVerify := routeHeader(cfg.Registration.SecurityVerify); securityVerify != "" {
		headers["Security-Verify"] = securityVerify
	}
	authSession := dialogDigestAuthSession(cfg)
	authHeaderName, authHeader, err := dialogDigestAuthorization(cfg, authSession, method, targetURI, body)
	if err != nil {
		return SIPRequestMessage{}, err
	}
	if authHeaderName != "" && authHeader != "" {
		headers[authHeaderName] = authHeader
	}
	return SIPRequestMessage{
		Method:      method,
		URI:         targetURI,
		Headers:     headers,
		Body:        append([]byte(nil), body...),
		AuthSession: authSession,
	}, nil
}

func dialogDigestAuthSession(cfg DialogRequestConfig) *DigestAuthSession {
	if cfg.AuthSession != nil {
		return cfg.AuthSession
	}
	return cfg.Registration.AuthSession
}

func dialogDigestAuthorization(cfg DialogRequestConfig, session *DigestAuthSession, method, targetURI string, body []byte) (string, string, error) {
	fallbackName := firstNonEmpty(cfg.AuthHeaderName, cfg.Registration.AuthHeaderName)
	fallbackHeader := firstNonEmpty(cfg.AuthHeader, cfg.Registration.AuthHeader)
	if session == nil {
		if fallbackHeader == "" {
			return "", "", nil
		}
		return firstNonEmpty(fallbackName, "Authorization"), fallbackHeader, nil
	}
	headerName, header, err := session.NextWithBody(method, targetURI, body)
	if err != nil {
		return "", "", err
	}
	if header == "" && fallbackHeader != "" {
		headerName = firstNonEmpty(headerName, fallbackName, "Authorization")
		header = fallbackHeader
	}
	return headerName, header, nil
}

func applySessionIntervalHeaders(headers map[string]string, cfg DialogRequestConfig) {
	if headers == nil || cfg.SessionExpires <= 0 {
		return
	}
	value := strconv.Itoa(cfg.SessionExpires)
	if refresher := normalizeSessionRefresher(cfg.SessionRefresher); refresher != "" {
		value += ";refresher=" + refresher
	}
	headers["Session-Expires"] = value
}

func normalizeSessionRefresher(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "uac", "uas":
		return strings.ToLower(strings.TrimSpace(value))
	default:
		return ""
	}
}

func routeHeader(routes []string) string {
	clean := trimHeaderValues(routes)
	if len(clean) == 0 {
		return ""
	}
	return strings.Join(clean, ", ")
}

func firstNonEmptySlice(items ...[]string) []string {
	for _, item := range items {
		if len(trimHeaderValues(item)) > 0 {
			return item
		}
	}
	return nil
}

func formatNameAddr(uri, tag string) string {
	out := "<" + strings.TrimSpace(uri) + ">"
	if tag = strings.TrimSpace(tag); tag != "" {
		out += ";tag=" + tag
	}
	return out
}

func formatReferHeader(value string) string {
	value = strings.TrimSpace(value)
	if value == "" || strings.Contains(value, "<") {
		return value
	}
	lower := strings.ToLower(value)
	if strings.HasPrefix(lower, "sip:") || strings.HasPrefix(lower, "sips:") || strings.HasPrefix(lower, "tel:") {
		return "<" + value + ">"
	}
	return value
}
