package e911

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/iniwex5/vowifi-go/engine/sim"
	"github.com/iniwex5/vowifi-go/engine/swu/eapaka"
	"github.com/iniwex5/vowifi-go/runtimehost/carrier"
)

var (
	ErrUnsupportedProvider     = errors.New("unsupported e911 provider")
	ErrChallengeNotImplemented = errors.New("e911 challenge not implemented")
	ErrWebsheetUnavailable     = errors.New("e911 websheet unavailable")
)

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
	Carrier     carrier.EffectiveCarrierConfig
	Identity    Identity
	AKAProvider sim.AKAProvider
	Client      HTTPClient
	Trace       TraceSink
}

type WebsheetRequest struct {
	URL         string
	UserData    string
	ContentType string
	Title       string
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
	return WebsheetRequest{
		URL:         req.Carrier.E911.Websheet,
		ContentType: "text/html",
		Title:       "Emergency address",
	}, nil
}

func startTS43EmergencyAddressUpdate(ctx context.Context, endpoint string, req Request) (WebsheetRequest, error) {
	client := req.Client
	if client == nil {
		client = NewDefaultHTTPClient()
	}
	payload, err := json.Marshal([]map[string]any{{
		"message-id":      1,
		"operation":       "emergency-address-update",
		"app-id":          "ap2003",
		"imsi":            req.Identity.IMSI,
		"imei":            req.Identity.IMEI,
		"mcc":             req.Identity.MCC,
		"mnc":             req.Identity.MNC,
		"sip-username":    req.Identity.SIPUsername,
		"terminal-vendor": "vowifi-go",
	}})
	if err != nil {
		return WebsheetRequest{}, err
	}
	resp, err := doEntitlement(ctx, client, req.Trace, &HTTPRequest{
		Method: "POST",
		URL:    endpoint,
		Headers: []HeaderPair{
			{Key: "Content-Type", Value: "application/json"},
			{Key: "Accept", Value: "application/json"},
			{Key: "x-protocol-version", Value: "2"},
		},
		Body: payload,
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
	for challengeResponses := 0; result.HasChallenge(); challengeResponses++ {
		if challengeResponses >= 3 {
			return WebsheetRequest{}, ErrChallengeNotImplemented
		}
		answerBody, err := buildEntitlementChallengeAnswer(req, result)
		if err != nil {
			return WebsheetRequest{}, err
		}
		answer, err := json.Marshal([]map[string]any{answerBody})
		if err != nil {
			return WebsheetRequest{}, err
		}
		resp, err = doEntitlement(ctx, client, req.Trace, &HTTPRequest{
			Method: "POST",
			URL:    endpoint,
			Headers: []HeaderPair{
				{Key: "Content-Type", Value: "application/json"},
				{Key: "Accept", Value: "application/json"},
				{Key: "x-protocol-version", Value: "2"},
			},
			Body: answer,
		})
		if err != nil {
			return WebsheetRequest{}, err
		}
		result, err = parseEntitlementResponse(resp.Body)
		if err != nil {
			return WebsheetRequest{}, err
		}
		if ws := websheetFromEntitlement(req.Carrier.E911.Websheet, result); ws.URL != "" {
			return ws, nil
		}
	}
	if result.Status == 6004 || result.ChallengeRequired {
		return WebsheetRequest{}, ErrChallengeNotImplemented
	}
	return WebsheetRequest{}, fmt.Errorf("e911 entitlement response did not include websheet data")
}

func buildEntitlementChallengeAnswer(req Request, result entitlementResult) (map[string]any, error) {
	answerBody := map[string]any{
		"message-id":    2,
		"operation":     "emergency-address-update",
		"response-id":   result.ResponseID,
		"sip-username":  req.Identity.SIPUsername,
		"terminal-imei": req.Identity.IMEI,
	}
	if relay, negotiated, err := buildEAPRelayKDFNegotiationAnswer(result); err != nil {
		return nil, err
	} else if negotiated {
		answerBody["eap-relay-packet"] = relay
		return answerBody, nil
	}
	if req.AKAProvider == nil {
		return nil, ErrChallengeNotImplemented
	}
	aka, err := req.AKAProvider.CalculateAKA(result.RAND, result.AUTN)
	syncFailure := errors.Is(err, sim.ErrSyncFailure)
	if err != nil && !syncFailure {
		return nil, err
	}
	if syncFailure && len(aka.AUTS) == 0 {
		return nil, err
	}
	answerBody["aka-res"] = strings.ToUpper(hex.EncodeToString(aka.RES))
	answerBody["aka-ck"] = strings.ToUpper(hex.EncodeToString(aka.CK))
	answerBody["aka-ik"] = strings.ToUpper(hex.EncodeToString(aka.IK))
	answerBody["aka-auts"] = strings.ToUpper(hex.EncodeToString(aka.AUTS))
	if relay, err := buildEAPRelayAnswer(result, aka, firstNonEmpty(req.Identity.SIPUsername, req.Identity.IMSI), syncFailure); err == nil && relay != "" {
		answerBody["eap-relay-packet"] = relay
	}
	return answerBody, nil
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
	Status            int
	ResponseID        any
	WebsheetURL       string
	UserData          string
	ContentType       string
	Title             string
	RAND              []byte
	AUTN              []byte
	ChallengeRequired bool
	EAPPacket         *eapaka.Packet
}

func (r entitlementResult) HasChallenge() bool {
	return len(r.RAND) == 16 && len(r.AUTN) == 16
}

func parseEntitlementResponse(body []byte) (entitlementResult, error) {
	var root any
	if err := json.Unmarshal(body, &root); err != nil {
		return entitlementResult{}, err
	}
	var out entitlementResult
	walkEntitlement(root, &out)
	if out.ContentType == "" {
		out.ContentType = "text/html"
	}
	if out.Title == "" {
		out.Title = "Emergency address"
	}
	return out, nil
}

func walkEntitlement(v any, out *entitlementResult) {
	switch x := v.(type) {
	case []any:
		for _, item := range x {
			walkEntitlement(item, out)
		}
	case map[string]any:
		for key, value := range x {
			lower := strings.ToLower(strings.TrimSpace(key))
			switch lower {
			case "status":
				if n, ok := numberValue(value); ok {
					out.Status = n
					if n == 6004 {
						out.ChallengeRequired = true
					}
				}
			case "response-id", "response_id", "responseid":
				out.ResponseID = value
			case "websheet", "websheet-url", "websheet_url", "e911-websheet-url", "e911_websheet_url", "address-url", "address_url", "url":
				if s := stringValue(value); looksHTTPURL(s) && out.WebsheetURL == "" {
					out.WebsheetURL = s
				}
			case "user-data", "userdata", "user_data", "token", "entitlement-token", "entitlement_token", "auth-token", "auth_token":
				if s := strings.TrimSpace(stringValue(value)); s != "" && out.UserData == "" {
					out.UserData = s
				}
			case "content-type", "content_type":
				out.ContentType = strings.TrimSpace(stringValue(value))
			case "title":
				out.Title = strings.TrimSpace(stringValue(value))
			case "rand":
				if decoded, ok := decodeChallengeBytes(stringValue(value)); ok {
					out.RAND = decoded
				}
			case "autn":
				if decoded, ok := decodeChallengeBytes(stringValue(value)); ok {
					out.AUTN = decoded
				}
			case "challenge", "aka-challenge", "aka_challenge", "eap-aka-challenge", "eap_aka_challenge":
				parseCombinedChallenge(value, out)
			case "eap-relay-packet", "eap_relay_packet", "eap-relay", "eap_relay":
				parseEAPRelayPacket(value, out)
			}
			walkEntitlement(value, out)
		}
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
	p := packet
	out.EAPPacket = &p
}

func buildEAPRelayAnswer(result entitlementResult, aka sim.AKAResult, identity string, syncFailure bool) (string, error) {
	if result.EAPPacket == nil {
		return "", nil
	}
	var packet eapaka.Packet
	var err error
	if syncFailure {
		packet, err = eapaka.BuildSynchronizationFailureResponse(*result.EAPPacket, aka.AUTS)
	} else {
		packet, _, err = eapaka.BuildChallengeResponse(strings.TrimSpace(identity), *result.EAPPacket, aka)
	}
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
	u := strings.TrimSpace(result.WebsheetURL)
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
