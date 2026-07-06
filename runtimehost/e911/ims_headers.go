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
