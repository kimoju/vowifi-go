package e911

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"testing"

	"github.com/kimoju/vowifi-go/engine/sim"
	"github.com/kimoju/vowifi-go/engine/swu"
	"github.com/kimoju/vowifi-go/engine/swu/eapaka"
	"github.com/kimoju/vowifi-go/runtimehost/carrier"
	"github.com/kimoju/vowifi-go/runtimehost/voiceclient"
)

func TestRound2Audit8B04NeverEmitsCKIKAndGatesAUTSOnSyncFailure(t *testing.T) {
	req := Request{
		Identity:    Identity{IMSI: "310280233641503", IMEI: "490154203237518", SIPUsername: "sip:user@example"},
		AKAProvider: &fakeAKAProvider{},
	}
	chal := entitlementResult{
		Status:     6004,
		ResponseID: "r-1",
		RAND:       bytesFrom(0x10, 16),
		AUTN:       bytesFrom(0x20, 16),
	}
	ans, _, _, _, _, _, err := buildEntitlementChallengeAnswer(req, chal, nil, nil, swu.EAPReauthenticationState{})
	if err != nil {
		t.Fatalf("buildEntitlementChallengeAnswer(success) error = %v", err)
	}
	if _, hasCK := ans["aka-ck"]; hasCK {
		t.Fatalf("answerBody leaked aka-ck: %+v", ans)
	}
	if _, hasIK := ans["aka-ik"]; hasIK {
		t.Fatalf("answerBody leaked aka-ik: %+v", ans)
	}
	if _, hasAUTS := ans["aka-auts"]; hasAUTS {
		t.Fatalf("normal AKA answer unexpectedly included aka-auts: %+v", ans)
	}
	if ans["aka-res"] == "" || ans["app-id"] != "ap2003" {
		t.Fatalf("normal AKA answer missing aka-res or app-id: %+v", ans)
	}

	// Sync failure emits aka-auts only (never aka-ck, aka-ik, or aka-res).
	syncProvider := &sequenceE911AKAProvider{results: []sequenceE911AKAResult{
		{result: sim.AKAResult{AUTS: bytesFrom(0xAA, 14), CK: bytesFrom(0xCC, 16), IK: bytesFrom(0xDD, 16)}, err: sim.ErrSyncFailure},
	}}
	ansSync, _, _, _, _, _, err := buildEntitlementChallengeAnswer(Request{
		Identity:    req.Identity,
		AKAProvider: syncProvider,
	}, chal, nil, nil, swu.EAPReauthenticationState{})
	if err != nil {
		t.Fatalf("buildEntitlementChallengeAnswer(syncFailure) error = %v", err)
	}
	if _, hasCK := ansSync["aka-ck"]; hasCK {
		t.Fatalf("sync answer leaked aka-ck: %+v", ansSync)
	}
	if _, hasIK := ansSync["aka-ik"]; hasIK {
		t.Fatalf("sync answer leaked aka-ik: %+v", ansSync)
	}
	if _, hasRES := ansSync["aka-res"]; hasRES {
		t.Fatalf("sync answer unexpectedly included aka-res: %+v", ansSync)
	}
	if ansSync["aka-auts"] == "" {
		t.Fatalf("sync answer missing aka-auts: %+v", ansSync)
	}
}

func TestRound2Audit8B05ApplePlistXMLAndTS43OMAWAPProvisioningXML(t *testing.T) {
	plistXML := []byte(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
  <dict>
    <key>EntitlementStatus</key><integer>1000</integer>
    <key>ServiceFlow_URL</key><string>https://entitlement.carrier.example/plist-websheet</string>
    <key>ServiceFlow_UserData</key><string>plist_post=1&amp;sess=abc</string>
    <key>AddrStatus</key><string>validated</string>
    <key>EmergencyAddress</key>
    <dict>
      <key>houseNumber</key><string>1600</string>
      <key>street</key><string>Pennsylvania Ave NW</string>
      <key>city</key><string>Washington</string>
      <key>state</key><string>DC</string>
      <key>postalCode</key><string>20500</string>
      <key>country</key><string>US</string>
    </dict>
    <key>EmergencyRoutes</key>
    <array>
      <dict>
        <key>serviceURN</key><string>urn:service:sos</string>
        <key>pcscf</key><array><string>2001:db8::10</string></array>
        <key>esrp</key><string>sips:esrp.carrier.example</string>
      </dict>
    </array>
  </dict>
</plist>`)
	plistInfo, err := ParseEntitlementResponse(plistXML)
	if err != nil {
		t.Fatalf("ParseEntitlementResponse(plist) error = %v", err)
	}
	if plistInfo.Status != 1000 || plistInfo.WebsheetURL != "https://entitlement.carrier.example/plist-websheet" ||
		plistInfo.UserData != "plist_post=1&sess=abc" || plistInfo.LocationValidationStatus != "validated" {
		t.Fatalf("plistInfo = %+v", plistInfo)
	}
	if plistInfo.Address.City != "Washington" || len(plistInfo.Routes) != 1 || len(plistInfo.Routes[0].PCSCF) != 1 || plistInfo.Routes[0].PCSCF[0] != "2001:db8::10" {
		t.Fatalf("plistInfo address/routes = %+v / %+v", plistInfo.Address, plistInfo.Routes)
	}

	wapXML := []byte(`<?xml version="1.0" encoding="UTF-8"?>
<wap-provisioningdoc version="1.1">
  <characteristic type="TOKEN">
    <parm name="token" value="tok-wap-999"/>
    <parm name="validity" value="3600"/>
  </characteristic>
  <characteristic type="ap2003">
    <parm name="EntitlementStatus" value="1000"/>
    <parm name="AddrStatus" value="verified"/>
    <parm name="ServiceFlow_URL" value="https://entitlement.carrier.example/wap-e911"/>
    <parm name="ServiceFlow_UserData" value="wap_post=1"/>
    <characteristic type="EmergencyAddress">
      <parm name="street" value="1 Infinite Loop"/>
      <parm name="city" value="Cupertino"/>
      <parm name="state" value="CA"/>
      <parm name="country" value="US"/>
    </characteristic>
    <characteristic type="EmergencyRouting">
      <parm name="ServiceURN" value="urn:service:sos"/>
      <parm name="PCSCF" value="pcscf.e911.carrier.example:5060"/>
      <parm name="ESRP" value="sips:esrp.e911.carrier.example"/>
    </characteristic>
  </characteristic>
</wap-provisioningdoc>`)
	wapInfo, err := ParseEntitlementResponse(wapXML)
	if err != nil {
		t.Fatalf("ParseEntitlementResponse(wap-provisioningdoc) error = %v", err)
	}
	if wapInfo.Status != 1000 || wapInfo.WebsheetURL != "https://entitlement.carrier.example/wap-e911" ||
		wapInfo.UserData != "wap_post=1" || wapInfo.LocationValidationStatus != "validated" {
		t.Fatalf("wapInfo = %+v", wapInfo)
	}
	if wapInfo.Address.City != "Cupertino" || len(wapInfo.Routes) != 1 ||
		wapInfo.Routes[0].PCSCF[0] != "pcscf.e911.carrier.example:5060" {
		t.Fatalf("wapInfo address/routes = %+v / %+v", wapInfo.Address, wapInfo.Routes)
	}
}

func TestRound2Audit8B06NeverSwallowsTS43ErrorsIntoStaticFallback(t *testing.T) {
	baseCfg := carrier.EffectiveCarrierConfig{
		E911: carrier.E911Config{
			Provider:            "att-ts43",
			Websheet:            "https://static.carrier.example/websheet",
			EntitlementEndpoint: "https://entitlement.carrier.example/ts43",
		},
	}

	// 1. Canceled context returns error, never static fallback.
	canceledCtx, cancel := context.WithCancel(context.Background())
	cancel()
	if ws, err := StartEmergencyAddressUpdate(canceledCtx, Request{
		Carrier: baseCfg,
		Client:  &fakeHTTPClient{},
	}); err == nil {
		t.Fatalf("StartEmergencyAddressUpdate(canceled) = %+v, want error", ws)
	}

	// 2. HTTP 500 error returns error, never static fallback.
	if ws, err := StartEmergencyAddressUpdate(context.Background(), Request{
		Carrier: baseCfg,
		Client:  &fakeHTTPClient{responses: []*HTTPResponse{{StatusCode: 500, Body: []byte("error")}}},
	}); err == nil {
		t.Fatalf("StartEmergencyAddressUpdate(HTTP 500) = %+v, want error", ws)
	}

	// 3. SIM AKA MAC failure (ErrAuthFailure) returns error, never static fallback.
	macFailProvider := &sequenceE911AKAProvider{results: []sequenceE911AKAResult{
		{err: sim.NewMACFailureError()},
	}}
	if ws, err := StartEmergencyAddressUpdate(context.Background(), Request{
		Carrier:     baseCfg,
		Identity:    Identity{IMSI: "310280233641503"},
		AKAProvider: macFailProvider,
		Client: &fakeHTTPClient{responses: []*HTTPResponse{{
			StatusCode: 200,
			Body:       []byte(`{"status":6004,"rand":"000102030405060708090a0b0c0d0e0f","autn":"101112131415161718191a1b1c1d1e1f"}`),
		}}},
	}); !errors.Is(err, sim.ErrAuthFailure) {
		t.Fatalf("StartEmergencyAddressUpdate(MAC failure) = (%+v, %v), want sim.ErrAuthFailure", ws, err)
	}
}

func TestRound2Audit8B08MultiRoundSessionCookiesDigestNextNonceAndMessageID(t *testing.T) {
	rawNonce := append(bytesFrom(0x10, 16), bytesFrom(0x40, 16)...)
	wwwAuth := `Digest realm="e911.example", nonce="` + base64.StdEncoding.EncodeToString(rawNonce) + `", algorithm=AKAv1-MD5, qop="auth"`

	// Build an EAP-Request/AKA-Identity packet for Round 1 -> Round 2, then AKA challenge for Round 2 -> Round 3.
	idPkt := eapaka.Packet{
		Code:       eapaka.CodeRequest,
		Identifier: 7,
		Type:       eapaka.TypeAKA,
		Subtype:    eapaka.SubtypeIdentity,
		Attributes: []eapaka.Attribute{eapaka.AnyIDReqAttribute()},
	}
	idRaw, err := idPkt.MarshalBinary()
	if err != nil {
		t.Fatalf("idPkt.MarshalBinary() error = %v", err)
	}

	client := &fakeHTTPClient{responses: []*HTTPResponse{
		// Request 0: Initial POST -> 401 with Set-Cookie: AWSELB=node-a
		{
			StatusCode: 401,
			Headers: []HeaderPair{
				{Key: "WWW-Authenticate", Value: wwwAuth},
				{Key: "Set-Cookie", Value: "AWSELB=node-a; Path=/"},
			},
		},
		// Request 1: Digest retry of Initial POST -> 200 EAP-Identity challenge + Set-Cookie: JSESSIONID=s-1 + Authentication-Info: nextnonce="srv-nonce-2"
		{
			StatusCode: 200,
			Headers: []HeaderPair{
				{Key: "Set-Cookie", Value: "JSESSIONID=s-1; Path=/; HttpOnly"},
				{Key: "Authentication-Info", Value: `qop=auth, nextnonce="srv-nonce-2"`},
			},
			Body: []byte(`[{"response-id":101,"eap-relay-packet":"` + base64.StdEncoding.EncodeToString(idRaw) + `"}]`),
		},
		// Request 2: Preemptive Digest (nonce="srv-nonce-2", nc=00000001) + Cookies, message-id=2 -> 200 AKA challenge (same nonce kept for Round 3)
		{
			StatusCode: 200,
			Body:       []byte(`[{"response-id":102,"rand":"000102030405060708090a0b0c0d0e0f","autn":"101112131415161718191a1b1c1d1e1f"}]`),
		},
		// Request 3: Preemptive Digest (nonce="srv-nonce-2", nc=00000002) + Cookies, message-id=3 -> 200 final websheet
		{
			StatusCode: 200,
			Body:       []byte(`[{"status":1000,"websheet-url":"https://entitlement.carrier.example/final-ws"}]`),
		},
	}}

	aka := &sequenceE911AKAProvider{results: []sequenceE911AKAResult{
		{result: e911AKAResult()}, // Used once for HTTP Digest 401
		{result: e911AKAResult()}, // Used once for Round 2 JSON AKA challenge
	}}

	ws, err := StartEmergencyAddressUpdate(context.Background(), Request{
		Carrier: carrier.EffectiveCarrierConfig{
			E911: carrier.E911Config{
				Provider:            "att-ts43",
				Websheet:            "https://entitlement.carrier.example/fallback",
				EntitlementEndpoint: "https://entitlement.carrier.example/ts43",
			},
		},
		Identity:    Identity{IMSI: "310280233641503", IMEI: "490154203237518", MCC: "310", MNC: "280", SIPUsername: "0310280233641503@nai.epc.mnc280.mcc310.3gppnetwork.org"},
		AKAProvider: aka,
		Client:      client,
		Random:      bytes.NewReader(bytes.Repeat([]byte{0x42}, 128)),
	})
	if err != nil {
		t.Fatalf("StartEmergencyAddressUpdate(multi-round) error = %v", err)
	}
	if ws.URL != "https://entitlement.carrier.example/final-ws" {
		t.Fatalf("ws.URL = %q", ws.URL)
	}
	if len(client.requests) != 4 || aka.calls != 2 {
		t.Fatalf("requests=%d AKA calls=%d, want 4 requests and 2 AKA calls", len(client.requests), aka.calls)
	}

	// Request 1 (401 retry) must already carry AWSELB cookie from 401 Set-Cookie.
	if gotCookie := headerValue(client.requests[1].Headers, "Cookie"); gotCookie != "AWSELB=node-a" {
		t.Fatalf("req[1] Cookie = %q, want AWSELB=node-a", gotCookie)
	}
	// Requests 2 and 3 must carry both cookies, preemptive Digest Authorization with nextnonce, and incrementing message-id + app-id.
	for idx, wantMsgID := range map[int]float64{2: 2, 3: 3} {
		if gotCookie := headerValue(client.requests[idx].Headers, "Cookie"); gotCookie != "AWSELB=node-a; JSESSIONID=s-1" {
			t.Fatalf("req[%d] Cookie = %q, want both cookies", idx, gotCookie)
		}
		auth := headerValue(client.requests[idx].Headers, "Authorization")
		parsedAuth, err := voiceclient.ParseDigestAuthorization(auth)
		if err != nil {
			t.Fatalf("req[%d] ParseDigestAuthorization(%q) error = %v", idx, auth, err)
		}
		wantNC := 1
		if idx == 3 {
			wantNC = 2
		}
		if parsedAuth.Nonce != "srv-nonce-2" || parsedAuth.NC != wantNC {
			t.Fatalf("req[%d] Digest = %+v, want nonce=srv-nonce-2 nc=%d", idx, parsedAuth, wantNC)
		}

		var payload []map[string]any
		if err := json.Unmarshal(client.requests[idx].Body, &payload); err != nil || len(payload) != 1 {
			t.Fatalf("req[%d] json.Unmarshal error = %v", idx, err)
		}
		if payload[0]["message-id"] != wantMsgID || payload[0]["app-id"] != "ap2003" {
			t.Fatalf("req[%d] body = %+v, want message-id=%v app-id=ap2003", idx, payload[0], wantMsgID)
		}
	}
}

func TestRound2Audit8B09StandardHTTPClientClonesDefaultTransportTimeouts(t *testing.T) {
	for _, tc := range []struct {
		name  string
		proxy *ProxyConfig
	}{
		{name: "direct", proxy: nil},
		{name: "http-proxy", proxy: &ProxyConfig{Enabled: true, Address: "http://127.0.0.1:8080"}},
		{name: "socks5-proxy", proxy: &ProxyConfig{Enabled: true, Address: "socks5://127.0.0.1:1080"}},
		{name: "invalid-proxy", proxy: &ProxyConfig{Enabled: true}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := newStandardHTTPClient(tc.proxy, 0)
			tr, ok := c.Transport.(*http.Transport)
			if !ok || tr == nil {
				t.Fatalf("Transport = %T, want non-nil *http.Transport", c.Transport)
			}
			if tr == http.DefaultTransport {
				t.Fatal("Transport aliases global http.DefaultTransport")
			}
			if tr.IdleConnTimeout <= 0 || tr.TLSHandshakeTimeout <= 0 {
				t.Fatalf("Transport timeouts IdleConnTimeout=%v TLSHandshakeTimeout=%v, want > 0", tr.IdleConnTimeout, tr.TLSHandshakeTimeout)
			}
			c.CloseIdleConnections()
		})
	}
}

func TestRound2Audit8B10FormatEmergencySIPRouteIPv6AndHostPort(t *testing.T) {
	got := EmergencySIPRouteSet([]EmergencyRoute{{
		PCSCF: []string{
			"2001:db8::1",
			"fe80::1",
			"[2001:db8::2]:5060",
			"pcscf.e911.carrier.net:5060",
			"192.0.2.10:5060",
		},
		ESRP:      []string{"sips:esrp.ims.example"},
		Endpoints: []string{"tel:+15551212", "urn:service:sos"},
	}})
	want := []string{
		"<sip:[2001:db8::1];lr>",
		"<sip:[fe80::1];lr>",
		"<sip:[2001:db8::2]:5060;lr>",
		"<sip:pcscf.e911.carrier.net:5060;lr>",
		"<sip:192.0.2.10:5060;lr>",
		"<sips:esrp.ims.example;lr>",
		"<tel:+15551212>",
		"<urn:service:sos>",
	}
	if !sameStrings(got, want) {
		t.Fatalf("EmergencySIPRouteSet() = %+v, want %+v", got, want)
	}
}

func TestRound2Audit8B16WGS84CoordinateValidation(t *testing.T) {
	// Valid boundary WGS-84 coordinates succeed.
	validBody, err := BuildEmergencyPIDFLO(EmergencyPIDFLOConfig{
		Address: EmergencyAddress{Latitude: "-90", Longitude: "180"},
	})
	if err != nil {
		t.Fatalf("BuildEmergencyPIDFLO(valid boundary) error = %v", err)
	}
	if _, err := ValidateEmergencyPIDFLO(validBody); err != nil {
		t.Fatalf("ValidateEmergencyPIDFLO(valid boundary) error = %v", err)
	}

	// Out-of-range, swapped, NaN/Inf, and non-numeric coordinates must fail in BuildEmergencyPIDFLO,
	// emergencyGeolocationHeader, ParseEmergencyPIDFLO, and ValidateEmergencyPIDFLO (even with civic fields!).
	badPairs := [][2]string{
		{"-122.3321", "47.6062"}, // swapped lon/lat (lat < -90)
		{"90.0001", "0"},
		{"0", "-180.0001"},
		{"NaN", "40"},
		{"40", "Inf"},
		{"invalid", "unknown"},
	}
	for _, pair := range badPairs {
		addr := EmergencyAddress{
			Street:    "1 Main St",
			City:      "Seattle",
			State:     "WA",
			Country:   "US",
			Latitude:  pair[0],
			Longitude: pair[1],
		}
		if _, err := BuildEmergencyPIDFLO(EmergencyPIDFLOConfig{Address: addr}); err == nil {
			t.Fatalf("BuildEmergencyPIDFLO(%v) = nil, want coordinate validation error", pair)
		}
		if hdr := emergencyGeolocationHeader(EmergencySIPHeaderConfig{Address: EmergencyAddress{Latitude: pair[0], Longitude: pair[1]}}); hdr != "" {
			t.Fatalf("emergencyGeolocationHeader(%v) = %q, want empty", pair, hdr)
		}

		badXML := []byte(`<?xml version="1.0" encoding="UTF-8"?>
<presence xmlns="urn:ietf:params:xml:ns:pidf" xmlns:gp="urn:ietf:params:xml:ns:pidf:geopriv10" xmlns:cl="urn:ietf:params:xml:ns:pidf:geopriv10:civicAddr" xmlns:gml="http://www.opengis.net/gml" entity="pres:sos@example">
  <tuple id="t1">
    <status>
      <gp:geopriv>
        <gp:location-info>
          <gml:Point srsName="urn:ogc:def:crs:EPSG::4326"><gml:pos>` + pair[0] + ` ` + pair[1] + `</gml:pos></gml:Point>
          <cl:civicAddress><cl:country>US</cl:country><cl:A1>WA</cl:A1><cl:A3>Seattle</cl:A3></cl:civicAddress>
        </gp:location-info>
        <gp:usage-rules/>
        <gp:method>Manual</gp:method>
      </gp:geopriv>
    </status>
  </tuple>
</presence>`)
		if _, err := ValidateEmergencyPIDFLO(badXML); err == nil {
			t.Fatalf("ValidateEmergencyPIDFLO(%v) = nil, want invalid geodetic coordinates error", pair)
		}
		if _, err := ParseEmergencyPIDFLO(badXML); err == nil {
			t.Fatalf("ParseEmergencyPIDFLO(%v) = nil, want invalid geodetic coordinates error", pair)
		}
	}
}
