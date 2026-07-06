package e911

import (
	"testing"
	"time"
)

func TestEntitlementCacheSnapshotRefreshAndRoutes(t *testing.T) {
	base := time.Date(2026, 7, 7, 9, 0, 0, 0, time.UTC)
	cache := NewEntitlementCache(EntitlementCachePolicy{RefreshBefore: time.Minute})
	snapshot := cache.Store(EntitlementInfo{
		Status:      1000,
		UserData:    "token-1",
		ServiceURNs: []string{"fire"},
		Routes: []EmergencyRoute{
			{ServiceURN: "urn:service:sos", PCSCF: []string{"pcscf.ims.example"}},
			{ServiceURN: "fire", ESRP: []string{"sip:fire@example.test"}},
			{Endpoints: []string{"sips:any@example.test"}},
		},
		ExpiresIn:      10 * time.Minute,
		CacheMaxAge:    5 * time.Minute,
		Endpoint:       "https://example.test/e911",
		ContentType:    "application/json",
		WebsheetURL:    "https://example.test/e911/websheet",
		CacheExpiresAt: time.Time{},
	}, base)

	if snapshot.RefreshRequired {
		t.Fatalf("RefreshRequired=%v reason=%q", snapshot.RefreshRequired, snapshot.RefreshReason)
	}
	if snapshot.Token != "token-1" {
		t.Fatalf("Token=%q", snapshot.Token)
	}
	if got, want := snapshot.ExpiresAt, base.Add(10*time.Minute); !got.Equal(want) {
		t.Fatalf("ExpiresAt=%s, want %s", got, want)
	}
	if got, want := snapshot.CacheExpiresAt, base.Add(5*time.Minute); !got.Equal(want) {
		t.Fatalf("CacheExpiresAt=%s, want %s", got, want)
	}
	if got, want := snapshot.RefreshAt, base.Add(4*time.Minute); !got.Equal(want) {
		t.Fatalf("RefreshAt=%s, want %s", got, want)
	}
	if !sameStrings(snapshot.AvailableServiceURNs(), []string{"urn:service:sos.fire", "urn:service:sos"}) {
		t.Fatalf("ServiceURNs=%+v", snapshot.AvailableServiceURNs())
	}
	fireRoutes := snapshot.AvailableRoutes("fire")
	if len(fireRoutes) != 2 {
		t.Fatalf("fire routes=%+v", fireRoutes)
	}
	if fireRoutes[0].ServiceURN != "urn:service:sos.fire" || len(fireRoutes[1].Endpoints) != 1 {
		t.Fatalf("fire routes=%+v", fireRoutes)
	}
	allRoutes := cache.AvailableRoutes("", base.Add(time.Minute))
	if len(allRoutes) != 3 {
		t.Fatalf("all routes=%+v", allRoutes)
	}

	refreshing := cache.Snapshot(base.Add(4 * time.Minute))
	if !refreshing.RefreshRequired || refreshing.RefreshReason != entitlementRefreshReasonRefreshWindow {
		t.Fatalf("refreshing=%+v", refreshing)
	}
	expired := cache.Snapshot(base.Add(5 * time.Minute))
	if !expired.RefreshRequired || expired.RefreshReason != entitlementRefreshReasonExpired {
		t.Fatalf("expired=%+v", expired)
	}
}

func TestEntitlementCacheDefensiveCopies(t *testing.T) {
	base := time.Date(2026, 7, 7, 9, 0, 0, 0, time.UTC)
	info := EntitlementInfo{
		Status:      1000,
		UserData:    "token-1",
		ServiceURNs: []string{"police"},
		Routes:      []EmergencyRoute{{ServiceURN: "police", PCSCF: []string{"pcscf.ims.example"}}},
		Address: EmergencyAddress{
			Fields: map[string]string{"city": "Seattle"},
		},
	}
	cache := NewEntitlementCache(EntitlementCachePolicy{})
	snapshot := cache.Store(info, base)
	info.UserData = "changed"
	info.ServiceURNs[0] = "fire"
	info.Routes[0].PCSCF[0] = "changed.example"
	info.Address.Fields["city"] = "Changed"
	snapshot.ServiceURNs[0] = "changed"
	snapshot.Routes[0].PCSCF[0] = "changed.example"
	snapshot.Info.Address.Fields["city"] = "Changed"

	next := cache.Snapshot(base.Add(time.Second))
	if next.Token != "token-1" {
		t.Fatalf("Token=%q", next.Token)
	}
	if !sameStrings(next.ServiceURNs, []string{"urn:service:sos.police"}) {
		t.Fatalf("ServiceURNs=%+v", next.ServiceURNs)
	}
	if next.Routes[0].PCSCF[0] != "pcscf.ims.example" {
		t.Fatalf("route copy leaked: %+v", next.Routes)
	}
	if next.Info.Address.Fields["city"] != "Seattle" {
		t.Fatalf("address copy leaked: %+v", next.Info.Address.Fields)
	}
}

func TestEntitlementCacheRequiresRefreshWithoutUsableData(t *testing.T) {
	now := time.Date(2026, 7, 7, 9, 0, 0, 0, time.UTC)
	cache := NewEntitlementCache(EntitlementCachePolicy{})
	if snapshot := cache.Snapshot(now); !snapshot.RefreshRequired || snapshot.RefreshReason != entitlementRefreshReasonNoCache {
		t.Fatalf("empty snapshot=%+v", snapshot)
	}

	statusSnapshot := cache.Store(EntitlementInfo{Status: 6004, UserData: "token-1"}, now)
	if !statusSnapshot.RefreshRequired || statusSnapshot.RefreshReason != entitlementRefreshReasonStatus {
		t.Fatalf("status snapshot=%+v", statusSnapshot)
	}

	emptySnapshot := cache.Store(EntitlementInfo{Status: 1000}, now)
	if !emptySnapshot.RefreshRequired || emptySnapshot.RefreshReason != entitlementRefreshReasonEmpty {
		t.Fatalf("empty data snapshot=%+v", emptySnapshot)
	}
}

func TestEntitlementCacheUsesPolicyDefaultsAndServiceFallback(t *testing.T) {
	base := time.Date(2026, 7, 7, 9, 0, 0, 0, time.UTC)
	cache := NewEntitlementCache(EntitlementCachePolicy{
		DefaultExpiresIn:   30 * time.Minute,
		DefaultCacheMaxAge: 10 * time.Minute,
		RefreshBefore:      time.Minute,
	})
	snapshot := cache.Store(EntitlementInfo{
		Status:   1000,
		UserData: "token-1",
	}, base)
	if !sameStrings(snapshot.ServiceURNs, []string{DefaultEmergencyServiceURN}) {
		t.Fatalf("ServiceURNs=%+v", snapshot.ServiceURNs)
	}
	if got, want := snapshot.ExpiresAt, base.Add(30*time.Minute); !got.Equal(want) {
		t.Fatalf("ExpiresAt=%s, want %s", got, want)
	}
	if got, want := snapshot.CacheExpiresAt, base.Add(10*time.Minute); !got.Equal(want) {
		t.Fatalf("CacheExpiresAt=%s, want %s", got, want)
	}
	if got, want := snapshot.RefreshAt, base.Add(9*time.Minute); !got.Equal(want) {
		t.Fatalf("RefreshAt=%s, want %s", got, want)
	}
	if !cache.NeedRefresh(base.Add(9 * time.Minute)) {
		t.Fatal("cache should enter refresh window")
	}
	cache.Reset()
	if snapshot := cache.Snapshot(base.Add(time.Second)); snapshot.Cached || !snapshot.RefreshRequired {
		t.Fatalf("reset snapshot=%+v", snapshot)
	}
}
