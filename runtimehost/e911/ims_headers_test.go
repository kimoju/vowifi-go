package e911

import (
	"testing"
	"time"
)

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

func TestBuildUsableEmergencySIPRequestInfoUsesEntitlementSnapshot(t *testing.T) {
	base := time.Date(2026, 7, 7, 9, 0, 0, 0, time.UTC)
	cache := NewEntitlementCache(EntitlementCachePolicy{RefreshBefore: time.Minute})
	snapshot := cache.Store(EntitlementInfo{
		Status:      1000,
		ServiceURNs: []string{"fire"},
		Routes: []EmergencyRoute{
			{ServiceURN: "fire", PCSCF: []string{"pcscf-fire.ims.example"}},
			{Endpoints: []string{"sips:any@example.test"}},
		},
		Address: EmergencyAddress{
			Latitude:  "47.6205",
			Longitude: "-122.3493",
		},
		CacheMaxAge: 5 * time.Minute,
	}, base)

	info, ok := BuildUsableEmergencySIPRequestInfo(snapshot, EmergencySIPHeaderConfig{
		ServiceURN: "fire",
		AccessNetworkInfo: EmergencyAccessNetworkInfo{
			WLANNodeID: "aa:bb:cc:dd:ee:ff",
		},
		GeolocationRouting: true,
	})
	if !ok {
		t.Fatalf("BuildUsableEmergencySIPRequestInfo() ok=false for usable snapshot: %+v", snapshot)
	}
	if info.RequestURI != "urn:service:sos.fire" {
		t.Fatalf("RequestURI=%q", info.RequestURI)
	}
	if info.Headers["Geolocation"] != "<geo:47.6205,-122.3493>;inserted-by=endpoint" {
		t.Fatalf("Geolocation=%q", info.Headers["Geolocation"])
	}
	if info.Headers["Geolocation-Routing"] != "yes" {
		t.Fatalf("Geolocation-Routing=%q", info.Headers["Geolocation-Routing"])
	}
	if got := info.Headers["P-Access-Network-Info"]; got != `IEEE-802.11;i-wlan-node-id="aa:bb:cc:dd:ee:ff"` {
		t.Fatalf("P-Access-Network-Info=%q", got)
	}
	if len(info.Routes) != 2 {
		t.Fatalf("routes=%+v, want service route plus generic route", info.Routes)
	}
	if info.Routes[0].ServiceURN != "urn:service:sos.fire" || !sameStrings(info.Routes[0].PCSCF, []string{"pcscf-fire.ims.example"}) {
		t.Fatalf("service route=%+v", info.Routes[0])
	}
	if !sameStrings(info.Routes[1].Endpoints, []string{"sips:any@example.test"}) {
		t.Fatalf("generic route=%+v", info.Routes[1])
	}
}

func TestEntitlementCacheUsableEmergencySIPRequestInfoBuildsFromRefreshWindowSnapshot(t *testing.T) {
	base := time.Date(2026, 7, 7, 9, 0, 0, 0, time.UTC)
	cache := NewEntitlementCache(EntitlementCachePolicy{RefreshBefore: 2 * time.Minute})
	cache.Store(EntitlementInfo{
		Status:      1000,
		ServiceURNs: []string{"ambulance", "fire"},
		Routes: []EmergencyRoute{
			{ServiceURN: "ambulance", PCSCF: []string{"pcscf-ambulance.ims.example"}},
			{Endpoints: []string{"sips:any@example.test"}},
		},
		Address: EmergencyAddress{
			Latitude:  "40.7128",
			Longitude: "-74.0060",
		},
		CacheMaxAge: 5 * time.Minute,
	}, base)

	info, snapshot, ok := cache.UsableEmergencySIPRequestInfo(EmergencySIPHeaderConfig{
		AccessNetworkInfo:  EmergencyAccessNetworkInfo{Raw: "IEEE-802.11"},
		GeolocationRouting: true,
	}, base.Add(4*time.Minute))
	if !ok {
		t.Fatalf("UsableEmergencySIPRequestInfo() ok=false for refresh-window snapshot: %+v", snapshot)
	}
	if !snapshot.RefreshRequired || snapshot.RefreshReason != EntitlementRefreshReasonRefreshWindow {
		t.Fatalf("snapshot=%+v, want refresh-window but still usable", snapshot)
	}
	if info.RequestURI != "urn:service:sos.ambulance" {
		t.Fatalf("RequestURI=%q", info.RequestURI)
	}
	if info.Headers["P-Access-Network-Info"] != "IEEE-802.11" {
		t.Fatalf("P-Access-Network-Info=%q", info.Headers["P-Access-Network-Info"])
	}
	if info.Headers["Geolocation"] != "<geo:40.7128,-74.0060>;inserted-by=endpoint" {
		t.Fatalf("Geolocation=%q", info.Headers["Geolocation"])
	}
	if len(info.Routes) != 2 {
		t.Fatalf("routes=%+v, want selected service route plus generic route", info.Routes)
	}
	if !sameStrings(info.Routes[0].PCSCF, []string{"pcscf-ambulance.ims.example"}) {
		t.Fatalf("service route=%+v", info.Routes[0])
	}
	if !sameStrings(info.Routes[1].Endpoints, []string{"sips:any@example.test"}) {
		t.Fatalf("generic route=%+v", info.Routes[1])
	}

	info.Routes[0].PCSCF[0] = "changed.example"
	nextInfo, _, ok := cache.UsableEmergencySIPRequestInfo(EmergencySIPHeaderConfig{ServiceURN: "ambulance"}, base.Add(4*time.Minute))
	if !ok {
		t.Fatal("second UsableEmergencySIPRequestInfo() ok=false")
	}
	if !sameStrings(nextInfo.Routes[0].PCSCF, []string{"pcscf-ambulance.ims.example"}) {
		t.Fatalf("route copy leaked into cache helper: %+v", nextInfo.Routes[0])
	}

	_, expired, ok := cache.UsableEmergencySIPRequestInfo(EmergencySIPHeaderConfig{ServiceURN: "ambulance"}, base.Add(5*time.Minute))
	if ok {
		t.Fatalf("expired snapshot should not build runtime SIP request info: %+v", expired)
	}
	if expired.RefreshReason != EntitlementRefreshReasonExpired {
		t.Fatalf("expired snapshot reason=%q", expired.RefreshReason)
	}
}

func TestBuildUsableEmergencySIPRequestInfoRejectsStaleOrUnsupportedEntitlement(t *testing.T) {
	base := time.Date(2026, 7, 7, 9, 0, 0, 0, time.UTC)
	cache := NewEntitlementCache(EntitlementCachePolicy{})
	cache.Store(EntitlementInfo{
		Status:      1000,
		ServiceURNs: []string{"police"},
		Routes: []EmergencyRoute{
			{ServiceURN: "police", PCSCF: []string{"pcscf-police.ims.example"}},
		},
		CacheMaxAge: 5 * time.Minute,
	}, base)

	fresh := cache.Snapshot(base.Add(time.Minute))
	if _, ok := BuildUsableEmergencySIPRequestInfo(fresh, EmergencySIPHeaderConfig{ServiceURN: "fire"}); ok {
		t.Fatal("unsupported requested service should not build from usable entitlement")
	}
	if !sameStrings(fresh.AvailableServiceURNs(), []string{"urn:service:sos.police"}) {
		t.Fatalf("available service URNs=%+v", fresh.AvailableServiceURNs())
	}

	expired := cache.Snapshot(base.Add(5 * time.Minute))
	if _, ok := BuildUsableEmergencySIPRequestInfo(expired, EmergencySIPHeaderConfig{ServiceURN: "police"}); ok {
		t.Fatal("expired entitlement should not build runtime SIP request info")
	}
	if routes := expired.AvailableRoutes("police"); len(routes) != 1 {
		t.Fatalf("available routes should preserve legacy view, got %+v", routes)
	}
	if routes := expired.UsableRoutes("police"); len(routes) != 0 {
		t.Fatalf("expired usable routes=%+v, want none", routes)
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
