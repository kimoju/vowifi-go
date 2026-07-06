package e911

import (
	"bytes"
	"context"
	crand "crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/boa-z/vowifi-go/engine/sim"
	"github.com/boa-z/vowifi-go/engine/swu"
	"github.com/boa-z/vowifi-go/engine/swu/eapaka"
	"github.com/boa-z/vowifi-go/runtimehost/carrier"
)

var (
	ErrUnsupportedProvider     = errors.New("unsupported e911 provider")
	ErrChallengeNotImplemented = errors.New("e911 challenge not implemented")
	ErrWebsheetUnavailable     = errors.New("e911 websheet unavailable")
)

const maxEntitlementChallengeResponses = 5

type HeaderPair struct {
	Key   string
	Value string
}

type HTTPRequest struct {
	Method  string
	URL     string
	Headers []HeaderPair
	Body    []byte
}

type HTTPResponse struct {
	StatusCode int
	Body       []byte
}

type HTTPClient interface {
	Do(req *HTTPRequest) (*HTTPResponse, error)
}

type defaultHTTPClient struct {
	client *http.Client
}

func NewDefaultHTTPClient() HTTPClient {
	return defaultHTTPClient{client: http.DefaultClient}
}

func (c defaultHTTPClient) Do(req *HTTPRequest) (*HTTPResponse, error) {
	if req == nil {
		return nil, errors.New("nil request")
	}
	method := req.Method
	if method == "" {
		method = http.MethodGet
	}
	hreq, err := http.NewRequest(method, req.URL, bytes.NewReader(req.Body))
	if err != nil {
		return nil, err
	}
	for _, h := range req.Headers {
		hreq.Header.Add(h.Key, h.Value)
	}
	client := c.client
	if client == nil {
		client = http.DefaultClient
	}
	resp, err := client.Do(hreq)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return &HTTPResponse{StatusCode: resp.StatusCode, Body: body}, nil
}

type Identity struct {
	IMSI        string
	IMEI        string
	MCC         string
	MNC         string
	SIPUsername string
	DisplayName string
	CachedToken string
}

type TraceSink interface {
	Request(*HTTPRequest)
	Response(*HTTPRequest, *HTTPResponse)
	Error(*HTTPRequest, error)
}

type Request struct {
	Carrier             carrier.EffectiveCarrierConfig
	Identity            Identity
	AKAProvider         sim.AKAProvider
	EAPReauthentication swu.EAPReauthenticationState
	Client              HTTPClient
	Trace               TraceSink
	Random              io.Reader
}

type WebsheetRequest struct {
	URL                 string
	UserData            string
	ContentType         string
	Title               string
	EAPNextPseudonym    string
	EAPNextReauthID     string
	EAPReauthentication swu.EAPReauthenticationState
}

func StartEmergencyAddressUpdate(ctx context.Context, req Request) (WebsheetRequest, error) {
	provider := strings.ToLower(strings.TrimSpace(req.Carrier.E911.Provider))
	if provider == "" {
		return WebsheetRequest{}, ErrUnsupportedProvider
	}
	if provider != "att" && provider != "att-ts43" && provider != "ts43" {
		return WebsheetRequest{}, ErrUnsupportedProvider
	}
	if req.Carrier.E911.Websheet == "" {
		return WebsheetRequest{}, ErrWebsheetUnavailable
	}
	if endpoint := strings.TrimSpace(req.Carrier.E911.EntitlementEndpoint); endpoint != "" {
		ws, err := startTS43EmergencyAddressUpdate(ctx, endpoint, req)
		if err == nil && strings.TrimSpace(ws.URL) != "" {
			return ws, nil
		}
		if errors.Is(err, ErrChallengeNotImplemented) {
			return WebsheetRequest{}, err
		}
	}
	return fallbackWebsheetRequest(req), nil
}

func startTS43EmergencyAddressUpdate(ctx context.Context, endpoint string, req Request) (WebsheetRequest, error) {
	client := req.Client
	if client == nil {
		client = NewDefaultHTTPClient()
	}
	requestBody := map[string]any{
		"message-id":      1,
		"operation":       "emergency-address-update",
		"app-id":          "ap2003",
		"imsi":            req.Identity.IMSI,
		"imei":            req.Identity.IMEI,
		"mcc":             req.Identity.MCC,
		"mnc":             req.Identity.MNC,
		"sip-username":    req.Identity.SIPUsername,
		"terminal-vendor": "vowifi-go",
	}
	if token := strings.TrimSpace(req.Identity.CachedToken); token != "" {
		requestBody["entitlement-token"] = token
		requestBody["token"] = token
	}
	payload, err := json.Marshal([]map[string]any{requestBody})
	if err != nil {
		return WebsheetRequest{}, err
	}
	resp, err := doEntitlement(ctx, client, req.Trace, &HTTPRequest{
		Method:  "POST",
		URL:     endpoint,
		Headers: entitlementHeaders(req),
		Body:    payload,
	})
	if err != nil {
		return WebsheetRequest{}, err
	}
	result, err := parseEntitlementResponse(resp.Body)
	if err != nil {
		return WebsheetRequest{}, err
	}
	if ws := websheetFromEntitlement(req.Carrier.E911.Websheet, result); ws.URL != "" {
		return ws, nil
	}
	var eapKeys *eapaka.Keys
	var identityTranscript [][]byte
	var eapIdentityState eapaka.EncryptedIdentityState
	eapReauthState := cloneEAPReauthenticationState(req.EAPReauthentication)
	eapReauthStateUpdated := false
	if eapReauthState.Usable() {
		keys := cloneEAPAKAKeys(eapReauthState.Keys)
		eapKeys = &keys
	}
	for challengeResponses := 0; result.HasChallenge(); challengeResponses++ {
		if challengeResponses >= maxEntitlementChallengeResponses {
			return WebsheetRequest{}, ErrChallengeNotImplemented
		}
		answerBody, nextEAPKeys, nextIdentityTranscript, nextEAPIdentityState, nextReauthState, reauthUpdated, err := buildEntitlementChallengeAnswer(req, result, eapKeys, identityTranscript, eapReauthState)
		if err != nil {
			return WebsheetRequest{}, err
		}
		if nextEAPKeys != nil {
			eapKeys = nextEAPKeys
		}
		identityTranscript = nextIdentityTranscript
		eapIdentityState = mergeEAPIdentityState(eapIdentityState, nextEAPIdentityState)
		if reauthUpdated {
			eapReauthState = nextReauthState
			eapReauthStateUpdated = true
		} else if nextEAPKeys != nil {
			if state, ok := eapReauthenticationStateFromFullAuth(eapReauthState, *nextEAPKeys, eapIdentityState); ok {
				eapReauthState = state
				eapReauthStateUpdated = true
			}
		}
		answer, err := json.Marshal([]map[string]any{answerBody})
		if err != nil {
			return WebsheetRequest{}, err
		}
		resp, err = doEntitlement(ctx, client, req.Trace, &HTTPRequest{
			Method:  "POST",
			URL:     endpoint,
			Headers: entitlementHeaders(req),
			Body:    answer,
		})
		if err != nil {
			return WebsheetRequest{}, err
		}
		result, err = parseEntitlementResponse(resp.Body)
		if err != nil {
			return WebsheetRequest{}, err
		}
		if ws := websheetFromEntitlement(req.Carrier.E911.Websheet, result); ws.URL != "" {
			ws = websheetWithEAPIdentityState(ws, eapIdentityState)
			if eapReauthStateUpdated {
				ws = websheetWithEAPReauthenticationState(ws, eapReauthState)
			}
			return ws, nil
		}
	}
	if result.Status == 6004 || result.ChallengeRequired {
		return WebsheetRequest{}, ErrChallengeNotImplemented
	}
	return WebsheetRequest{}, fmt.Errorf("e911 entitlement response did not include websheet data")
}

func buildEntitlementChallengeAnswer(req Request, result entitlementResult, eapKeys *eapaka.Keys, identityTranscript [][]byte, reauthState swu.EAPReauthenticationState) (map[string]any, *eapaka.Keys, [][]byte, eapaka.EncryptedIdentityState, swu.EAPReauthenticationState, bool, error) {
	answerBody := map[string]any{
		"message-id":    2,
		"operation":     "emergency-address-update",
		"response-id":   result.ResponseID,
		"sip-username":  req.Identity.SIPUsername,
		"terminal-imei": req.Identity.IMEI,
	}
	if token := strings.TrimSpace(req.Identity.CachedToken); token != "" {
		answerBody["entitlement-token"] = token
		answerBody["token"] = token
	}
	nextIdentityTranscript := cloneByteSlices(identityTranscript)
	if isEAPRelayTerminalPacket(result) {
		return answerBody, nil, nextIdentityTranscript, eapaka.EncryptedIdentityState{}, reauthState, false, nil
	}
	if relay, raw, ok, err := buildEAPRelayIdentityAnswer(result, eapRelayIdentityOptions{
		PermanentIdentity: firstNonEmpty(req.Identity.SIPUsername, req.Identity.IMSI),
		ReauthState:       reauthState,
	}); err != nil {
		return nil, nil, nil, eapaka.EncryptedIdentityState{}, swu.EAPReauthenticationState{}, false, err
	} else if ok {
		answerBody["eap-relay-packet"] = relay
		if len(result.EAPPacketRaw) > 0 {
			nextIdentityTranscript = append(nextIdentityTranscript, append([]byte(nil), result.EAPPacketRaw...))
		} else if result.EAPPacket != nil {
			requestRaw, err := result.EAPPacket.MarshalBinary()
			if err != nil {
				return nil, nil, nil, eapaka.EncryptedIdentityState{}, swu.EAPReauthenticationState{}, false, err
			}
			nextIdentityTranscript = append(nextIdentityTranscript, requestRaw)
		}
		nextIdentityTranscript = append(nextIdentityTranscript, append([]byte(nil), raw...))
		return answerBody, nil, nextIdentityTranscript, eapaka.EncryptedIdentityState{}, reauthState, false, nil
	}
	if relay, negotiated, err := buildEAPRelayKDFNegotiationAnswer(result); err != nil {
		return nil, nil, nil, eapaka.EncryptedIdentityState{}, swu.EAPReauthenticationState{}, false, err
	} else if negotiated {
		answerBody["eap-relay-packet"] = relay
		return answerBody, nil, nextIdentityTranscript, eapaka.EncryptedIdentityState{}, reauthState, false, nil
	}
	if relay, ok, err := buildEAPRelayNotificationAnswer(result, eapKeys); err != nil {
		return nil, nil, nil, eapaka.EncryptedIdentityState{}, swu.EAPReauthenticationState{}, false, err
	} else if ok {
		answerBody["eap-relay-packet"] = relay
		return answerBody, nil, nextIdentityTranscript, eapaka.EncryptedIdentityState{}, reauthState, false, nil
	}
	if relay, keys, nextReauthState, handled, err := buildEAPRelayReauthenticationAnswer(req, result, reauthState); err != nil {
		return nil, nil, nil, eapaka.EncryptedIdentityState{}, swu.EAPReauthenticationState{}, false, err
	} else if handled {
		answerBody["eap-relay-packet"] = relay
		return answerBody, keys, nextIdentityTranscript, eapaka.EncryptedIdentityState{}, nextReauthState, true, nil
	}
	if result.EAPPacket != nil && result.EAPPacket.Subtype != eapaka.SubtypeChallenge {
		relay, err := buildEAPRelayClientErrorAnswer(result, eapaka.ClientErrorUnableToProcessPacket)
		if err != nil {
			return nil, nil, nil, eapaka.EncryptedIdentityState{}, swu.EAPReauthenticationState{}, false, err
		}
		answerBody["eap-relay-packet"] = relay
		return answerBody, nil, nextIdentityTranscript, eapaka.EncryptedIdentityState{}, reauthState, false, nil
	}
	if req.AKAProvider == nil {
		return nil, nil, nil, eapaka.EncryptedIdentityState{}, swu.EAPReauthenticationState{}, false, ErrChallengeNotImplemented
	}
	aka, err := req.AKAProvider.CalculateAKA(result.RAND, result.AUTN)
	syncFailure := errors.Is(err, sim.ErrSyncFailure)
	authFailure := errors.Is(err, sim.ErrAuthFailure)
	if err != nil && !syncFailure && !authFailure {
		return nil, nil, nil, eapaka.EncryptedIdentityState{}, swu.EAPReauthenticationState{}, false, err
	}
	if syncFailure && len(aka.AUTS) == 0 {
		return nil, nil, nil, eapaka.EncryptedIdentityState{}, swu.EAPReauthenticationState{}, false, err
	}
	if authFailure {
		if result.EAPPacket == nil {
			return nil, nil, nil, eapaka.EncryptedIdentityState{}, swu.EAPReauthenticationState{}, false, err
		}
		relay, err := buildEAPRelayAuthenticationRejectAnswer(result)
		if err != nil {
			return nil, nil, nil, eapaka.EncryptedIdentityState{}, swu.EAPReauthenticationState{}, false, err
		}
		answerBody["eap-relay-packet"] = relay
		return answerBody, nil, nextIdentityTranscript, eapaka.EncryptedIdentityState{}, reauthState, false, nil
	}
	var nextEAPKeys *eapaka.Keys
	var nextEAPIdentityState eapaka.EncryptedIdentityState
	var relayAuthenticationReject bool
	if result.EAPPacket != nil {
		relay, keys, identityState, authenticationReject, err := buildEAPRelayAnswer(result, aka, firstNonEmpty(req.Identity.SIPUsername, req.Identity.IMSI), syncFailure, nextIdentityTranscript)
		if err != nil {
			return nil, nil, nil, eapaka.EncryptedIdentityState{}, swu.EAPReauthenticationState{}, false, err
		}
		if relay != "" {
			answerBody["eap-relay-packet"] = relay
			nextEAPKeys = keys
			nextEAPIdentityState = identityState
			relayAuthenticationReject = authenticationReject
		}
	}
	if !relayAuthenticationReject {
		answerBody["aka-res"] = strings.ToUpper(hex.EncodeToString(aka.RES))
		answerBody["aka-ck"] = strings.ToUpper(hex.EncodeToString(aka.CK))
		answerBody["aka-ik"] = strings.ToUpper(hex.EncodeToString(aka.IK))
		answerBody["aka-auts"] = strings.ToUpper(hex.EncodeToString(aka.AUTS))
	}
	return answerBody, nextEAPKeys, nextIdentityTranscript, nextEAPIdentityState, reauthState, false, nil
}

func isEAPRelayTerminalPacket(result entitlementResult) bool {
	if result.EAPPacket == nil {
		return false
	}
	switch result.EAPPacket.Code {
	case eapaka.CodeSuccess, eapaka.CodeFailure:
		return true
	default:
		return false
	}
}

func entitlementHeaders(req Request) []HeaderPair {
	headers := []HeaderPair{
		{Key: "Content-Type", Value: "application/json"},
		{Key: "Accept", Value: "application/json"},
		{Key: "x-protocol-version", Value: "2"},
	}
	if token := strings.TrimSpace(req.Identity.CachedToken); token != "" {
		headers = append(headers,
			HeaderPair{Key: "Authorization", Value: "Bearer " + token},
			HeaderPair{Key: "x-entitlement-token", Value: token},
		)
	}
	return headers
}

func fallbackWebsheetRequest(req Request) WebsheetRequest {
	url := strings.TrimSpace(req.Carrier.E911.Websheet)
	token := strings.TrimSpace(req.Identity.CachedToken)
	if token != "" {
		url = appendUserData(url, token)
	}
	return WebsheetRequest{
		URL:         url,
		UserData:    token,
		ContentType: "text/html",
		Title:       "Emergency address",
	}
}

func doEntitlement(ctx context.Context, client HTTPClient, trace TraceSink, req *HTTPRequest) (*HTTPResponse, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if trace != nil {
		trace.Request(req)
	}
	resp, err := client.Do(req)
	if err != nil {
		if trace != nil {
			trace.Error(req, err)
		}
		return nil, err
	}
	if trace != nil {
		trace.Response(req, resp)
	}
	if resp == nil {
		return nil, errors.New("e911 entitlement HTTP client returned nil response")
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("e911 entitlement HTTP status %d", resp.StatusCode)
	}
	return resp, nil
}

type entitlementResult struct {
	Status                   int
	ResponseID               any
	WebsheetURL              string
	UserData                 string
	ContentType              string
	Title                    string
	RAND                     []byte
	AUTN                     []byte
	ChallengeRequired        bool
	EAPPacket                *eapaka.Packet
	EAPPacketRaw             []byte
	EmergencyAddress         map[string]string
	PDN                      string
	PDNType                  string
	APN                      string
	Realm                    string
	Endpoint                 string
	LocationValidationStatus string
}

func (r entitlementResult) HasChallenge() bool {
	return (len(r.RAND) == 16 && len(r.AUTN) == 16) || r.EAPPacket != nil
}

func parseEntitlementResponse(body []byte) (entitlementResult, error) {
	body = bytes.TrimSpace(body)
	var root any
	if err := json.Unmarshal(body, &root); err == nil {
		var out entitlementResult
		walkEntitlement(root, &out)
		return finalizeEntitlementResult(out), nil
	} else if xmlResult, xmlErr := parseXMLEntitlementResponse(body); xmlErr == nil {
		return xmlResult, nil
	} else if looksXMLBody(body) {
		return entitlementResult{}, xmlErr
	} else {
		return entitlementResult{}, err
	}
}

func finalizeEntitlementResult(out entitlementResult) entitlementResult {
	if out.ContentType == "" {
		out.ContentType = "text/html"
	}
	if out.Title == "" {
		out.Title = "Emergency address"
	}
	return out
}

type entitlementXMLNode struct {
	XMLName  xml.Name
	Attrs    []xml.Attr           `xml:",any,attr"`
	Text     string               `xml:",chardata"`
	Children []entitlementXMLNode `xml:",any"`
}

func parseXMLEntitlementResponse(body []byte) (entitlementResult, error) {
	var root entitlementXMLNode
	if err := xml.Unmarshal(body, &root); err != nil {
		return entitlementResult{}, err
	}
	if root.XMLName.Local == "" {
		return entitlementResult{}, errors.New("empty e911 entitlement XML response")
	}
	var out entitlementResult
	walkXMLEntitlement(root, &out, false)
	return finalizeEntitlementResult(out), nil
}

func walkEntitlement(v any, out *entitlementResult) {
	walkEntitlementValue(v, out, false)
}

func walkEntitlementValue(v any, out *entitlementResult, inEmergencyAddress bool) {
	switch x := v.(type) {
	case []any:
		for _, item := range x {
			walkEntitlementValue(item, out, inEmergencyAddress)
		}
	case map[string]any:
		for key, value := range x {
			consumeEntitlementField(key, value, out)
			nextInEmergencyAddress := inEmergencyAddress || isEmergencyAddressKey(normalizeEntitlementKey(key))
			if nextInEmergencyAddress {
				collectEmergencyAddressField(key, value, out)
			}
			walkEntitlementValue(value, out, nextInEmergencyAddress)
		}
	}
}

func walkXMLEntitlement(node entitlementXMLNode, out *entitlementResult, inEmergencyAddress bool) {
	key := node.XMLName.Local
	canonical := normalizeEntitlementKey(key)
	text := strings.TrimSpace(node.Text)
	if text != "" {
		consumeEntitlementField(key, text, out)
	}
	nextInEmergencyAddress := inEmergencyAddress || isEmergencyAddressKey(canonical)
	if nextInEmergencyAddress && text != "" && len(node.Children) == 0 {
		collectEmergencyAddressField(key, text, out)
	}
	for _, attr := range node.Attrs {
		consumeEntitlementField(attr.Name.Local, attr.Value, out)
		if isPDNKey(canonical) {
			consumePDNField(attr.Name.Local, attr.Value, out)
		}
		if nextInEmergencyAddress {
			collectEmergencyAddressField(attr.Name.Local, attr.Value, out)
		}
	}
	for _, child := range node.Children {
		walkXMLEntitlement(child, out, nextInEmergencyAddress)
	}
}

func consumeEntitlementField(key string, value any, out *entitlementResult) {
	switch normalizeEntitlementKey(key) {
	case "status", "statuscode", "entitlementstatus", "resultcode", "responsecode":
		if n, ok := numberValue(value); ok {
			out.Status = n
			if n == 6004 {
				out.ChallengeRequired = true
			}
		}
	case "responseid", "responseidentifier", "requestid", "transactionid":
		if out.ResponseID == nil {
			out.ResponseID = value
		}
	case "websheet", "websheeturl", "e911websheet", "e911websheeturl", "addressurl", "addressupdateurl", "emergencyaddressurl", "emergencyaddresswebsheeturl", "emergencyaddressupdateurl", "e911addressurl", "e911addressupdateurl", "locationurl", "locationvalidationurl", "url":
		setHTTPURL(&out.WebsheetURL, value)
	case "endpoint", "addressendpoint", "emergencyaddressendpoint", "e911endpoint", "websheetendpoint", "locationendpoint", "locationvalidationendpoint":
		setHTTPURL(&out.Endpoint, value)
	case "userdata", "userdatatoken", "token", "entitlementtoken", "authtoken", "authorizationtoken", "accesstoken", "bearertoken":
		setString(&out.UserData, value)
	case "contenttype", "mimetype":
		setString(&out.ContentType, value)
	case "title", "websheettitle", "pagetitle", "displaytitle":
		setString(&out.Title, value)
	case "rand", "akarand", "eapakarand":
		if decoded, ok := decodeChallengeBytes(stringValue(value)); ok {
			out.RAND = decoded
		}
	case "autn", "akaautn", "eapakautn":
		if decoded, ok := decodeChallengeBytes(stringValue(value)); ok {
			out.AUTN = decoded
		}
	case "challenge", "akachallenge", "eapakachallenge", "aka":
		parseCombinedChallenge(value, out)
	case "eaprelaypacket", "eaprelay", "eappacket", "eapakapacket":
		parseEAPRelayPacket(value, out)
	case "challengerequired", "akachallengerequired", "eapchallengerequired":
		if b, ok := boolValue(value); ok && b {
			out.ChallengeRequired = true
		}
	case "pdn", "pdnname", "pdnid", "emergencypdn":
		parsePDN(value, out)
		setString(&out.PDN, value)
	case "pdntype", "emergencypdntype":
		setString(&out.PDNType, value)
	case "apn", "accesspointname", "emergencyapn", "imsapn":
		setString(&out.APN, value)
	case "realm", "networkrealm", "imsrealm", "nairealm", "homerealm":
		setString(&out.Realm, value)
	case "locationvalidationstatus", "validationstatus", "addressvalidationstatus", "e911addressvalidationstatus", "locationstatus":
		setString(&out.LocationValidationStatus, value)
	default:
		if isEmergencyAddressKey(normalizeEntitlementKey(key)) {
			parseEmergencyAddress(value, out)
		}
	}
}

func normalizeEntitlementKey(key string) string {
	key = strings.ToLower(strings.TrimSpace(key))
	var b strings.Builder
	for _, r := range key {
		if r >= 'a' && r <= 'z' || r >= '0' && r <= '9' {
			b.WriteRune(r)
		}
	}
	return b.String()
}

func looksXMLBody(body []byte) bool {
	return strings.HasPrefix(strings.TrimSpace(string(body)), "<")
}

func setString(dst *string, value any) {
	if dst == nil || strings.TrimSpace(*dst) != "" {
		return
	}
	if s := strings.TrimSpace(stringValue(value)); s != "" {
		*dst = s
	}
}

func setHTTPURL(dst *string, value any) {
	if dst == nil || strings.TrimSpace(*dst) != "" {
		return
	}
	if s := strings.TrimSpace(stringValue(value)); looksHTTPURL(s) {
		*dst = s
	}
}

func boolValue(v any) (bool, bool) {
	switch x := v.(type) {
	case bool:
		return x, true
	case string:
		switch strings.ToLower(strings.TrimSpace(x)) {
		case "true", "yes", "1", "required":
			return true, true
		case "false", "no", "0", "notrequired", "none":
			return false, true
		}
	case float64:
		return x != 0, true
	case int:
		return x != 0, true
	case json.Number:
		n, err := strconv.ParseInt(string(x), 10, 64)
		if err == nil {
			return n != 0, true
		}
	}
	return false, false
}

func isEmergencyAddressKey(canonical string) bool {
	switch canonical {
	case "emergencyaddress", "e911address", "address", "civicaddress", "serviceaddress", "registeredaddress":
		return true
	default:
		return false
	}
}

func isPDNKey(canonical string) bool {
	switch canonical {
	case "pdn", "pdninfo", "pdnconnection", "emergencypdn", "emergencybearer", "imsbearer":
		return true
	default:
		return false
	}
}

func parsePDN(value any, out *entitlementResult) {
	switch x := value.(type) {
	case map[string]any:
		for key, item := range x {
			consumePDNField(key, item, out)
		}
	case []any:
		for _, item := range x {
			parsePDN(item, out)
		}
	default:
		setString(&out.PDN, value)
	}
}

func consumePDNField(key string, value any, out *entitlementResult) {
	if out == nil {
		return
	}
	switch normalizeEntitlementKey(key) {
	case "name", "id", "pdn", "pdnname", "pdnid", "emergencypdn":
		setString(&out.PDN, value)
	case "type", "pdntype", "emergencypdntype":
		setString(&out.PDNType, value)
	case "apn", "accesspointname", "emergencyapn", "imsapn":
		setString(&out.APN, value)
	case "realm", "networkrealm", "imsrealm", "nairealm", "homerealm":
		setString(&out.Realm, value)
	case "endpoint", "url", "uri", "addressendpoint", "e911endpoint", "locationendpoint":
		setHTTPURL(&out.Endpoint, value)
	}
}

func parseEmergencyAddress(value any, out *entitlementResult) {
	switch x := value.(type) {
	case map[string]any:
		for key, item := range x {
			collectEmergencyAddressField(key, item, out)
		}
	case []any:
		for _, item := range x {
			parseEmergencyAddress(item, out)
		}
	}
}

func collectEmergencyAddressField(key string, value any, out *entitlementResult) {
	if out == nil {
		return
	}
	canonical := normalizeEntitlementKey(key)
	if isEmergencyAddressKey(canonical) {
		parseEmergencyAddress(value, out)
		return
	}
	switch canonical {
	case "street", "street1", "streetaddress", "addressline1":
		canonical = "street"
	case "street2", "addressline2", "unit", "apartment", "suite":
		canonical = "unit"
	case "city", "locality":
		canonical = "city"
	case "state", "region", "province":
		canonical = "state"
	case "postalcode", "zip", "zipcode":
		canonical = "postal_code"
	case "country", "countrycode":
		canonical = "country"
	default:
		return
	}
	if s := strings.TrimSpace(stringValue(value)); s != "" {
		if out.EmergencyAddress == nil {
			out.EmergencyAddress = make(map[string]string)
		}
		out.EmergencyAddress[canonical] = s
	}
}

func parseEAPRelayPacket(v any, out *entitlementResult) {
	raw, ok := decodeChallengeBytes(stringValue(v))
	if !ok || len(raw) == 0 {
		return
	}
	packet, err := eapaka.ParsePacket(raw)
	if err != nil {
		return
	}
	p := packet
	out.EAPPacket = &p
	out.EAPPacketRaw = append([]byte(nil), raw...)
	rand16, autn16, err := eapaka.ChallengeRANDAndAUTN(packet)
	if err != nil {
		return
	}
	if len(out.RAND) == 0 {
		out.RAND = rand16
	}
	if len(out.AUTN) == 0 {
		out.AUTN = autn16
	}
}

type eapRelayIdentityOptions struct {
	PermanentIdentity string
	ReauthState       swu.EAPReauthenticationState
}

func buildEAPRelayIdentityAnswer(result entitlementResult, opts eapRelayIdentityOptions) (string, []byte, bool, error) {
	if result.EAPPacket == nil {
		return "", nil, false, nil
	}
	request := *result.EAPPacket
	if request.Code != eapaka.CodeRequest || request.Subtype != eapaka.SubtypeIdentity {
		return "", nil, false, nil
	}
	identity := eapRelayRequestedIdentity(request, opts)
	if identity == "" {
		return "", nil, true, ErrChallengeNotImplemented
	}
	packet, err := eapaka.BuildIdentityResponse(identity, request)
	if err != nil {
		return "", nil, true, err
	}
	raw, err := packet.MarshalBinary()
	if err != nil {
		return "", nil, true, err
	}
	return base64.StdEncoding.EncodeToString(raw), raw, true, nil
}

func eapRelayRequestedIdentity(request eapaka.Packet, opts eapRelayIdentityOptions) string {
	permanent := strings.TrimSpace(opts.PermanentIdentity)
	state := cloneEAPReauthenticationState(opts.ReauthState)
	pseudonym := strings.TrimSpace(state.NextPseudonym)
	switch {
	case eapRelayHasIdentityRequest(request, eapaka.AttributePermanentIDReq):
		return permanent
	case eapRelayHasIdentityRequest(request, eapaka.AttributeFullAuthIDReq):
		return firstNonEmpty(pseudonym, permanent)
	case eapRelayHasIdentityRequest(request, eapaka.AttributeAnyIDReq):
		if state.Usable() {
			return firstNonEmpty(state.Identity, pseudonym, permanent)
		}
		return firstNonEmpty(pseudonym, permanent)
	default:
		return permanent
	}
}

func eapRelayHasIdentityRequest(request eapaka.Packet, typ uint8) bool {
	_, ok := eapaka.FindAttribute(request.Attributes, typ)
	return ok
}

func buildEAPRelayAnswer(result entitlementResult, aka sim.AKAResult, identity string, syncFailure bool, identityTranscript [][]byte) (string, *eapaka.Keys, eapaka.EncryptedIdentityState, bool, error) {
	if result.EAPPacket == nil {
		return "", nil, eapaka.EncryptedIdentityState{}, false, nil
	}
	var packet eapaka.Packet
	var keys *eapaka.Keys
	var identityState eapaka.EncryptedIdentityState
	var err error
	var authenticationReject bool
	if syncFailure {
		packet, err = eapaka.BuildSynchronizationFailureResponse(*result.EAPPacket, aka.AUTS)
	} else {
		response, responseKeys, responseErr := eapaka.BuildChallengeResponseWithCheckcode(strings.TrimSpace(identity), *result.EAPPacket, aka, identityTranscript)
		packet, err = response, responseErr
		if errors.Is(responseErr, eapaka.ErrBiddingDown) {
			packet, err = eapaka.BuildAuthenticationRejectResponse(*result.EAPPacket)
			authenticationReject = true
		}
		if err == nil && !authenticationReject {
			keys = &responseKeys
			if attrs, _, decryptErr := eapaka.DecryptChallengeEncryptedAttributes(*result.EAPPacket, responseKeys); decryptErr != nil {
				err = decryptErr
			} else if len(attrs) > 0 {
				identityState, err = eapaka.IdentityStateFromAttributes(attrs)
			}
		}
	}
	if err != nil {
		return "", nil, eapaka.EncryptedIdentityState{}, false, err
	}
	raw, err := packet.MarshalBinary()
	if err != nil {
		return "", nil, eapaka.EncryptedIdentityState{}, false, err
	}
	return base64.StdEncoding.EncodeToString(raw), keys, identityState, authenticationReject, nil
}

func cloneByteSlices(in [][]byte) [][]byte {
	if len(in) == 0 {
		return nil
	}
	out := make([][]byte, len(in))
	for i, item := range in {
		out[i] = append([]byte(nil), item...)
	}
	return out
}

func mergeEAPIdentityState(current, next eapaka.EncryptedIdentityState) eapaka.EncryptedIdentityState {
	if next.NextPseudonym != "" {
		current.NextPseudonym = next.NextPseudonym
	}
	if next.NextReauthID != "" {
		current.NextReauthID = next.NextReauthID
	}
	return current
}

func websheetWithEAPIdentityState(ws WebsheetRequest, state eapaka.EncryptedIdentityState) WebsheetRequest {
	ws.EAPNextPseudonym = state.NextPseudonym
	ws.EAPNextReauthID = state.NextReauthID
	return ws
}

func websheetWithEAPReauthenticationState(ws WebsheetRequest, state swu.EAPReauthenticationState) WebsheetRequest {
	state = cloneEAPReauthenticationState(state)
	ws.EAPReauthentication = state
	if ws.EAPNextPseudonym == "" {
		ws.EAPNextPseudonym = state.NextPseudonym
	}
	if ws.EAPNextReauthID == "" {
		ws.EAPNextReauthID = state.Identity
	}
	return ws
}

func buildEAPRelayAuthenticationRejectAnswer(result entitlementResult) (string, error) {
	if result.EAPPacket == nil {
		return "", nil
	}
	packet, err := eapaka.BuildAuthenticationRejectResponse(*result.EAPPacket)
	if err != nil {
		return "", err
	}
	raw, err := packet.MarshalBinary()
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(raw), nil
}

func buildEAPRelayKDFNegotiationAnswer(result entitlementResult) (string, bool, error) {
	if result.EAPPacket == nil {
		return "", false, nil
	}
	packet, negotiated, err := eapaka.BuildAKAPrimeKDFNegotiationResponse(*result.EAPPacket)
	if err != nil || !negotiated {
		return "", negotiated, err
	}
	raw, err := packet.MarshalBinary()
	if err != nil {
		return "", false, err
	}
	return base64.StdEncoding.EncodeToString(raw), true, nil
}

func buildEAPRelayNotificationAnswer(result entitlementResult, eapKeys *eapaka.Keys) (string, bool, error) {
	if result.EAPPacket == nil {
		return "", false, nil
	}
	packet, ok, err := eapaka.BuildNotificationResponse(*result.EAPPacket)
	if errors.Is(err, eapaka.ErrInvalidKeyMaterial) && eapKeys != nil {
		packet, ok, err = eapaka.BuildAuthenticatedNotificationResponse(*result.EAPPacket, eapKeys.KAut)
	}
	if err != nil || !ok {
		return "", ok, err
	}
	raw, err := packet.MarshalBinary()
	if err != nil {
		return "", false, err
	}
	return base64.StdEncoding.EncodeToString(raw), true, nil
}

func buildEAPRelayReauthenticationAnswer(req Request, result entitlementResult, state swu.EAPReauthenticationState) (string, *eapaka.Keys, swu.EAPReauthenticationState, bool, error) {
	if result.EAPPacket == nil || result.EAPPacket.Subtype != eapaka.SubtypeReauthentication {
		return "", nil, state, false, nil
	}
	state = cloneEAPReauthenticationState(state)
	if !state.Usable() {
		return "", nil, state, false, nil
	}
	parsed, err := eapaka.ParseReauthenticationRequest(*result.EAPPacket, state.Keys)
	if err != nil {
		return "", nil, swu.EAPReauthenticationState{}, true, err
	}
	iv, err := entitlementRandomBytes(req.Random, 16)
	if err != nil {
		return "", nil, swu.EAPReauthenticationState{}, true, err
	}
	next := state
	var packet eapaka.Packet
	var keys eapaka.Keys
	if state.CounterOK && parsed.Counter <= state.Counter {
		packet, err = eapaka.BuildReauthenticationCounterTooSmallResponse(*result.EAPPacket, state.Keys, iv)
		if err != nil {
			return "", nil, swu.EAPReauthenticationState{}, true, err
		}
		keys = state.Keys
		next.CounterTooSmall = true
		next.Reauthenticated = false
		next.LastRejectedCounter = parsed.Counter
	} else {
		identity := strings.TrimSpace(state.Identity)
		if identity == "" {
			return "", nil, swu.EAPReauthenticationState{}, true, ErrChallengeNotImplemented
		}
		packet, keys, err = eapaka.BuildReauthenticationResponse(identity, *result.EAPPacket, state.Keys, iv)
		if err != nil {
			return "", nil, swu.EAPReauthenticationState{}, true, err
		}
		next.Keys = cloneEAPAKAKeys(keys)
		next.Counter = parsed.Counter
		next.CounterOK = true
		next.CounterTooSmall = false
		next.Reauthenticated = true
		next.LastAcceptedCounter = parsed.Counter
		if parsed.IdentityState.NextReauthID != "" {
			next.Identity = strings.TrimSpace(parsed.IdentityState.NextReauthID)
		}
		if parsed.IdentityState.NextPseudonym != "" {
			next.NextPseudonym = strings.TrimSpace(parsed.IdentityState.NextPseudonym)
		}
	}
	raw, err := packet.MarshalBinary()
	if err != nil {
		return "", nil, swu.EAPReauthenticationState{}, true, err
	}
	next = cloneEAPReauthenticationState(next)
	return base64.StdEncoding.EncodeToString(raw), eapKeysPtr(keys), next, true, nil
}

func buildEAPRelayClientErrorAnswer(result entitlementResult, code uint16) (string, error) {
	if result.EAPPacket == nil {
		return "", nil
	}
	packet, err := eapaka.BuildClientErrorResponse(*result.EAPPacket, code)
	if err != nil {
		return "", err
	}
	raw, err := packet.MarshalBinary()
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(raw), nil
}

func eapReauthenticationStateFromFullAuth(current swu.EAPReauthenticationState, keys eapaka.Keys, state eapaka.EncryptedIdentityState) (swu.EAPReauthenticationState, bool) {
	next := cloneEAPReauthenticationState(current)
	if strings.TrimSpace(state.NextReauthID) != "" {
		next.Identity = strings.TrimSpace(state.NextReauthID)
	}
	if strings.TrimSpace(state.NextPseudonym) != "" {
		next.NextPseudonym = strings.TrimSpace(state.NextPseudonym)
	}
	if strings.TrimSpace(next.Identity) == "" {
		return swu.EAPReauthenticationState{}, false
	}
	next.Keys = cloneEAPAKAKeys(keys)
	next.Counter = 0
	next.CounterOK = true
	next.Reauthenticated = false
	next.CounterTooSmall = false
	next.LastAcceptedCounter = 0
	next.LastRejectedCounter = 0
	return cloneEAPReauthenticationState(next), true
}

func parseCombinedChallenge(v any, out *entitlementResult) {
	text := stringValue(v)
	if text == "" {
		return
	}
	raw, ok := decodeChallengeBytes(text)
	if !ok || len(raw) < 32 {
		return
	}
	if len(out.RAND) == 0 {
		out.RAND = append([]byte(nil), raw[:16]...)
	}
	if len(out.AUTN) == 0 {
		out.AUTN = append([]byte(nil), raw[16:32]...)
	}
}

func websheetFromEntitlement(fallbackURL string, result entitlementResult) WebsheetRequest {
	u := firstNonEmpty(result.WebsheetURL, result.Endpoint)
	userData := strings.TrimSpace(result.UserData)
	if u == "" && userData != "" {
		u = appendUserData(fallbackURL, userData)
	}
	if u == "" {
		return WebsheetRequest{}
	}
	return WebsheetRequest{
		URL:         u,
		UserData:    userData,
		ContentType: firstNonEmpty(result.ContentType, "text/html"),
		Title:       firstNonEmpty(result.Title, "Emergency address"),
	}
}

func appendUserData(rawURL, userData string) string {
	rawURL = strings.TrimSpace(rawURL)
	if rawURL == "" {
		return ""
	}
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return rawURL
	}
	q := parsed.Query()
	if q.Get("token") == "" {
		q.Set("token", userData)
	}
	parsed.RawQuery = q.Encode()
	return parsed.String()
}

func numberValue(v any) (int, bool) {
	switch x := v.(type) {
	case float64:
		return int(x), true
	case int:
		return x, true
	case json.Number:
		n, err := x.Int64()
		return int(n), err == nil
	case string:
		var n int
		_, err := fmt.Sscanf(strings.TrimSpace(x), "%d", &n)
		return n, err == nil
	default:
		return 0, false
	}
}

func stringValue(v any) string {
	switch x := v.(type) {
	case string:
		return x
	default:
		return ""
	}
}

func decodeChallengeBytes(s string) ([]byte, bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, false
	}
	clean := strings.NewReplacer(" ", "", ":", "", "-", "").Replace(s)
	if raw, err := hex.DecodeString(clean); err == nil {
		return raw, true
	}
	if raw, err := base64.StdEncoding.DecodeString(s); err == nil {
		return raw, true
	}
	if raw, err := base64.RawStdEncoding.DecodeString(s); err == nil {
		return raw, true
	}
	return nil, false
}

func entitlementRandomBytes(r io.Reader, n int) ([]byte, error) {
	if r == nil {
		r = crand.Reader
	}
	out := make([]byte, n)
	if _, err := io.ReadFull(r, out); err != nil {
		return nil, err
	}
	return out, nil
}

func eapKeysPtr(keys eapaka.Keys) *eapaka.Keys {
	cloned := cloneEAPAKAKeys(keys)
	return &cloned
}

func cloneEAPReauthenticationState(state swu.EAPReauthenticationState) swu.EAPReauthenticationState {
	state.Identity = strings.TrimSpace(state.Identity)
	state.NextPseudonym = strings.TrimSpace(state.NextPseudonym)
	state.Keys = cloneEAPAKAKeys(state.Keys)
	return state
}

func cloneEAPAKAKeys(keys eapaka.Keys) eapaka.Keys {
	return eapaka.Keys{
		MK:      append([]byte(nil), keys.MK...),
		KEncr:   append([]byte(nil), keys.KEncr...),
		KAut:    append([]byte(nil), keys.KAut...),
		KRe:     append([]byte(nil), keys.KRe...),
		MSK:     append([]byte(nil), keys.MSK...),
		EMSK:    append([]byte(nil), keys.EMSK...),
		CKPrime: append([]byte(nil), keys.CKPrime...),
		IKPrime: append([]byte(nil), keys.IKPrime...),
	}
}

func looksHTTPURL(s string) bool {
	s = strings.ToLower(strings.TrimSpace(s))
	return strings.HasPrefix(s, "https://") || strings.HasPrefix(s, "http://")
}

func firstNonEmpty(items ...string) string {
	for _, item := range items {
		if strings.TrimSpace(item) != "" {
			return strings.TrimSpace(item)
		}
	}
	return ""
}
