package e911

import "testing"

func TestEmergencyServiceURNsForCategory(t *testing.T) {
	got := EmergencyServiceURNsForCategory(
		EmergencyServiceCategoryPolice |
			EmergencyServiceCategoryAmbulance |
			EmergencyServiceCategoryFire |
			EmergencyServiceCategoryManualECall,
	)
	want := []string{
		"urn:service:sos.police",
		"urn:service:sos.ambulance",
		"urn:service:sos.fire",
		"urn:service:sos.ecall.manual",
	}
	if !sameStrings(got, want) {
		t.Fatalf("URNs=%+v, want %+v", got, want)
	}
	if fallback := EmergencyServiceURNsForCategory(0); !sameStrings(fallback, []string{DefaultEmergencyServiceURN}) {
		t.Fatalf("fallback URNs=%+v", fallback)
	}
}

func TestBuildEmergencySIPRequestInfoUsesIMSHeadersAndGeoURI(t *testing.T) {
	info := BuildEmergencySIPRequestInfo(EmergencySIPHeaderConfig{
		ServiceURN: "fire",
		AccessNetworkInfo: EmergencyAccessNetworkInfo{
			WLANNodeID: `aa:bb:cc:dd:ee:ff"lab`,
		},
		Address: EmergencyAddress{
			Latitude:  "47.6205",
			Longitude: "-122.3493",
		},
		GeolocationRouting: true,
	})
	if info.RequestURI != "urn:service:sos.fire" {
		t.Fatalf("RequestURI=%q", info.RequestURI)
	}
	headers := info.Headers
	if headers["P-Preferred-Service"] != IMSMMTelServiceIdentifier {
		t.Fatalf("P-Preferred-Service=%q", headers["P-Preferred-Service"])
	}
	if headers["Accept-Contact"] != IMSEmergencyAcceptContact {
		t.Fatalf("Accept-Contact=%q", headers["Accept-Contact"])
	}
	wantPANI := `IEEE-802.11;i-wlan-node-id="aa:bb:cc:dd:ee:ff\"lab"`
	if headers["P-Access-Network-Info"] != wantPANI {
		t.Fatalf("P-Access-Network-Info=%q, want %q", headers["P-Access-Network-Info"], wantPANI)
	}
	if headers["Geolocation"] != "<geo:47.6205,-122.3493>;inserted-by=endpoint" {
		t.Fatalf("Geolocation=%q", headers["Geolocation"])
	}
	if headers["Geolocation-Routing"] != "yes" {
		t.Fatalf("Geolocation-Routing=%q", headers["Geolocation-Routing"])
	}
}

func TestBuildEmergencySIPHeadersAllowsCarrierOverrides(t *testing.T) {
	headers := BuildEmergencySIPHeaders(EmergencySIPHeaderConfig{
		AccessNetworkInfo: EmergencyAccessNetworkInfo{
			Raw: "3GPP-E-UTRAN-FDD;utran-cell-id-3gpp=3102600abcdef",
		},
		GeolocationURI: "<cid:location-1>;routing-allowed=yes",
	})
	if headers["P-Access-Network-Info"] != "3GPP-E-UTRAN-FDD;utran-cell-id-3gpp=3102600abcdef" {
		t.Fatalf("P-Access-Network-Info=%q", headers["P-Access-Network-Info"])
	}
	if headers["Geolocation"] != "<cid:location-1>;routing-allowed=yes" {
		t.Fatalf("Geolocation=%q", headers["Geolocation"])
	}
	if headers["Geolocation-Routing"] != "" {
		t.Fatalf("Geolocation-Routing=%q, want omitted", headers["Geolocation-Routing"])
	}
}

func TestEmergencyRequestURIFallsBackToSOS(t *testing.T) {
	if got := EmergencyRequestURI(""); got != DefaultEmergencyServiceURN {
		t.Fatalf("empty service RequestURI=%q", got)
	}
	if got := EmergencyRequestURI("unknown-private-service"); got != DefaultEmergencyServiceURN {
		t.Fatalf("unknown service RequestURI=%q", got)
	}
	if got := NormalizeEmergencyServiceURN("URN:SERVICE:SOS.POLICE"); got != "urn:service:sos.police" {
		t.Fatalf("normalized URN=%q", got)
	}
}
