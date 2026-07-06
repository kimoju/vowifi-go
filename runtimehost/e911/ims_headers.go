package e911

import "strings"

const (
	DefaultEmergencyServiceURN = "urn:service:sos"

	IMSMMTelServiceIdentifier = "urn:urn-7:3gpp-service.ims.icsi.mmtel"
	IMSEmergencyAcceptContact = `*;+g.3gpp.icsi-ref="urn%3Aurn-7%3A3gpp-service.ims.icsi.mmtel";require;explicit`
)

type EmergencyServiceCategory uint8

const (
	EmergencyServiceCategoryPolice EmergencyServiceCategory = 1 << iota
	EmergencyServiceCategoryAmbulance
	EmergencyServiceCategoryFire
	EmergencyServiceCategoryMarine
	EmergencyServiceCategoryMountain
	EmergencyServiceCategoryManualECall
	EmergencyServiceCategoryAutomaticECall
)

type EmergencyAccessNetworkInfo struct {
	Raw        string
	AccessType string
	WLANNodeID string
}

type EmergencySIPHeaderConfig struct {
	ServiceURN         string
	AccessNetworkInfo  EmergencyAccessNetworkInfo
	GeolocationURI     string
	Address            EmergencyAddress
	GeolocationRouting bool
}

type EmergencySIPRequestInfo struct {
	RequestURI string
	Headers    map[string]string
	Routes     []EmergencyRoute
}

func NormalizeEmergencyServiceURN(s string) string {
	return normalizeEmergencyServiceURN(s)
}

func EmergencyRequestURI(service string) string {
	if urn := NormalizeEmergencyServiceURN(service); urn != "" {
		return urn
	}
	return DefaultEmergencyServiceURN
}

func EmergencyServiceURNsForCategory(category EmergencyServiceCategory) []string {
	if category == 0 {
		return []string{DefaultEmergencyServiceURN}
	}
	var out []string
	for _, mapping := range []struct {
		category EmergencyServiceCategory
		urn      string
	}{
		{EmergencyServiceCategoryPolice, "urn:service:sos.police"},
		{EmergencyServiceCategoryAmbulance, "urn:service:sos.ambulance"},
		{EmergencyServiceCategoryFire, "urn:service:sos.fire"},
		{EmergencyServiceCategoryMarine, "urn:service:sos.marine"},
		{EmergencyServiceCategoryMountain, "urn:service:sos.mountain"},
		{EmergencyServiceCategoryManualECall, "urn:service:sos.ecall.manual"},
		{EmergencyServiceCategoryAutomaticECall, "urn:service:sos.ecall.automatic"},
	} {
		if category&mapping.category != 0 {
			out = append(out, mapping.urn)
		}
	}
	if len(out) == 0 {
		return []string{DefaultEmergencyServiceURN}
	}
	return out
}

func BuildPAccessNetworkInfo(info EmergencyAccessNetworkInfo) string {
	if raw := strings.TrimSpace(info.Raw); raw != "" {
		return raw
	}
	accessType := strings.TrimSpace(info.AccessType)
	if accessType == "" {
		accessType = "IEEE-802.11"
	}
	if nodeID := strings.TrimSpace(info.WLANNodeID); nodeID != "" {
		return accessType + `;i-wlan-node-id=` + quoteSIPParamValue(nodeID)
	}
	return accessType
}

func BuildEmergencySIPHeaders(cfg EmergencySIPHeaderConfig) map[string]string {
	headers := map[string]string{
		"P-Preferred-Service":   IMSMMTelServiceIdentifier,
		"Accept-Contact":        IMSEmergencyAcceptContact,
		"P-Access-Network-Info": BuildPAccessNetworkInfo(cfg.AccessNetworkInfo),
	}
	if geolocation := emergencyGeolocationHeader(cfg); geolocation != "" {
		headers["Geolocation"] = geolocation
		if cfg.GeolocationRouting {
			headers["Geolocation-Routing"] = "yes"
		}
	}
	return headers
}

func BuildEmergencySIPRequestInfo(cfg EmergencySIPHeaderConfig) EmergencySIPRequestInfo {
	return EmergencySIPRequestInfo{
		RequestURI: EmergencyRequestURI(cfg.ServiceURN),
		Headers:    BuildEmergencySIPHeaders(cfg),
	}
}

// UsableEmergencySIPRequestInfo builds runtime SIP request metadata from this
// snapshot when the cached entitlement data is still locally usable.
func (s EntitlementSnapshot) UsableEmergencySIPRequestInfo(cfg EmergencySIPHeaderConfig) (EmergencySIPRequestInfo, bool) {
	return buildUsableEmergencySIPRequestInfo(s, cfg)
}

func BuildUsableEmergencySIPRequestInfo(snapshot EntitlementSnapshot, cfg EmergencySIPHeaderConfig) (EmergencySIPRequestInfo, bool) {
	return buildUsableEmergencySIPRequestInfo(snapshot, cfg)
}

func buildUsableEmergencySIPRequestInfo(snapshot EntitlementSnapshot, cfg EmergencySIPHeaderConfig) (EmergencySIPRequestInfo, bool) {
	if !snapshot.Usable() {
		return EmergencySIPRequestInfo{}, false
	}
	serviceURN, routes, ok := usableEmergencySIPService(snapshot, cfg.ServiceURN)
	if !ok {
		return EmergencySIPRequestInfo{}, false
	}
	cfg.ServiceURN = serviceURN
	if strings.TrimSpace(cfg.GeolocationURI) == "" && !emergencyAddressHasGeolocation(cfg.Address) {
		cfg.Address = snapshot.Info.Address
	}
	info := BuildEmergencySIPRequestInfo(cfg)
	info.Routes = copyEmergencyRoutes(routes)
	return info, true
}

func emergencyGeolocationHeader(cfg EmergencySIPHeaderConfig) string {
	if uri := strings.TrimSpace(cfg.GeolocationURI); uri != "" {
		return formatGeolocationURI(uri)
	}
	lat := strings.TrimSpace(cfg.Address.Latitude)
	lon := strings.TrimSpace(cfg.Address.Longitude)
	if lat == "" || lon == "" {
		return ""
	}
	return formatGeolocationURI("geo:" + lat + "," + lon)
}

func usableEmergencySIPService(snapshot EntitlementSnapshot, requested string) (string, []EmergencyRoute, bool) {
	requested = normalizeEmergencyServiceURN(requested)
	if requested != "" {
		routes := snapshot.UsableRoutes(requested)
		if containsEmergencyServiceURN(snapshot.UsableServiceURNs(), requested) || len(routes) > 0 {
			return requested, routes, true
		}
		return "", nil, false
	}
	for _, urn := range snapshot.UsableServiceURNs() {
		urn = normalizeEmergencyServiceURN(urn)
		if urn != "" {
			return urn, snapshot.UsableRoutes(urn), true
		}
	}
	return "", nil, false
}

func containsEmergencyServiceURN(urns []string, urn string) bool {
	urn = normalizeEmergencyServiceURN(urn)
	if urn == "" {
		return false
	}
	for _, candidate := range urns {
		if strings.EqualFold(normalizeEmergencyServiceURN(candidate), urn) {
			return true
		}
	}
	return false
}

func emergencyAddressHasGeolocation(address EmergencyAddress) bool {
	return strings.TrimSpace(address.Latitude) != "" && strings.TrimSpace(address.Longitude) != ""
}

func formatGeolocationURI(uri string) string {
	uri = strings.TrimSpace(uri)
	if uri == "" {
		return ""
	}
	if strings.HasPrefix(uri, "<") {
		return uri
	}
	return "<" + uri + ">;inserted-by=endpoint"
}

func quoteSIPParamValue(value string) string {
	var b strings.Builder
	b.WriteByte('"')
	for _, r := range value {
		if r == '\\' || r == '"' {
			b.WriteByte('\\')
		}
		b.WriteRune(r)
	}
	b.WriteByte('"')
	return b.String()
}
