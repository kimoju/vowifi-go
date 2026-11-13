package identity

import (
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"github.com/kimoju/vowifi-go/runtimehost/carrier"
	"github.com/kimoju/vowifi-go/runtimehost/simauth"
	"github.com/kimoju/vowifi-go/runtimehost/simtransport"
)

const (
	IMSIdentitySourceProfile = "profile"
	IMSIdentitySourceISIM    = "isim"

	IMSISourceProfile = "profile"
	PLMNSourceIMSI    = "imsi"

	IdentityFieldMCC = "mcc"
	IdentityFieldMNC = "mnc"

	IMEISourceProfile     = "profile"
	IMEISourceModem       = "modem"
	IMEISourceDeviceID    = "device_id"
	IMEISourceUnavailable = "unavailable"

	AKAAppPreferenceUSIM       = "usim"
	AKAAppPreferenceAuto       = "auto"
	AKAAppPreferenceISIM       = "isim"
	AKAAppPreferenceISIMStrict = "isim_strict"

	IMSIdentityDomainStatusMatch    = "match"
	IMSIdentityDomainStatusMissing  = "missing"
	IMSIdentityDomainStatusUnknown  = "unknown"
	IMSIdentityDomainStatusMismatch = "mismatch"
)

type Profile struct {
	IMSI      string
	MCC       string
	MNC       string
	IMEI      string
	SMSC      string
	MNCLength int
}

type Identity struct {
	IMPI   string
	IMPU   []string
	Domain string
}

type IMSIdentityResolution struct {
	RequestedSource  string
	ActualSource     string
	AKAAppPreference string
	Applied          bool
	IMPI             string
	IMPU             string
	Domain           string
	FallbackUsed     bool
	FallbackReason   string
	RecoveryClass    simtransport.RecoveryClass
}

type IMSIdentityDomainValidation struct {
	Domain        string
	Status        string
	MatchedDomain string
	MatchedRole   string
	Candidates    []carrier.IMSIdentityDomainCandidate
}

type EffectiveCarrier struct {
	MCC      string
	MNC      string
	PresetID string
}

type PreparedSession struct {
	Profile            Profile
	EffectiveCarrier   EffectiveCarrier
	CarrierPolicy      carrier.CarrierPolicy
	EPDGAddr           string
	PCSCFFQDNs         []string
	EPDGSource         string
	IdentityIMSISource string
	IdentityIMEISource string
	IMSIdentity        IMSIdentityResolution
	Fallbacks          []FallbackMetadata
}

type PrepareStartInput struct {
	DeviceID            string
	Profile             Profile
	EFAD                []byte
	RuntimeEPDGOverride string
	Access              interface {
		GetISIMIdentity() (Identity, error)
	}
}

func NormalizeProfile(p Profile) Profile {
	return NormalizeProfileWithAD(p, nil)
}

func NormalizeProfileWithAD(p Profile, efAD []byte) Profile {
	p.IMSI = strings.TrimSpace(p.IMSI)
	p.MCC = normalizeMCC(p.MCC)
	p.MNC = normalizeProfileMNC(p.MNC)
	p.IMEI = normalizeProfileIMEI(p.IMEI, p.IMSI)
	p.SMSC = strings.TrimSpace(p.SMSC)
	if len(efAD) == 0 && (p.MNCLength == 2 || p.MNCLength == 3) {
		efAD = []byte{0x00, 0x00, 0x00, byte(p.MNCLength)}
	}
	imsiMCC, imsiMNC := plmnFromIMSIWithAD(p.IMSI, efAD)
	if imsiMCC != "" && (p.MCC == "" || !strings.HasPrefix(normalizeIMSI(p.IMSI), p.MCC)) {
		if p.MCC != "" {
			p.MNC = ""
		}
		p.MCC = imsiMCC
	}
	if imsiMNC != "" && (p.MNC == "" || !imsiMatchesPLMN(p.IMSI, p.MCC, p.MNC)) {
		p.MNC = imsiMNC
	}
	return p
}

func PrepareStart(in PrepareStartInput) (PreparedSession, error) {
	efAD := in.EFAD
	if len(efAD) == 0 && (in.Profile.MNCLength == 2 || in.Profile.MNCLength == 3) {
		efAD = []byte{0x00, 0x00, 0x00, byte(in.Profile.MNCLength)}
	}
	if len(efAD) == 0 && (strings.TrimSpace(in.Profile.MNC) == "" || !imsiMatchesPLMN(in.Profile.IMSI, in.Profile.MCC, in.Profile.MNC)) {
		if ad, err := accessEFAD(in.Access); err == nil && len(ad) > 0 {
			efAD = ad
		}
	}
	rawProfileIMEI := strings.TrimSpace(in.Profile.IMEI)
	profile, fallbacks, err := prepareProfileWithAD(in.Profile, efAD)
	if err != nil {
		return PreparedSession{}, err
	}
	profileIMEIReason := errors.New("profile IMEI is empty")
	if rawProfileIMEI != "" && profile.IMEI == "" {
		profileIMEIReason = fmt.Errorf("profile IMEI %q is invalid", rawProfileIMEI)
	}
	effectiveCfg := carrier.ResolveEffectiveCarrierConfig(carrier.EffectiveCarrierConfigInput{
		IMSI: profile.IMSI,
		MCC:  profile.MCC,
		MNC:  profile.MNC,
		EFAD: efAD,
	})
	policy := carrier.CarrierPolicyForConfig(profile.IMSI, effectiveCfg)
	if effectiveCfg.MCC != "" {
		profile.MCC = effectiveCfg.MCC
	}
	if effectiveCfg.MNC != "" && len(profile.MNC) != 2 {
		profile.MNC = effectiveCfg.MNC
	}
	if profile.SMSC == "" {
		if smsc := accessSMSC(in.Access); smsc != "" {
			profile.SMSC = smsc
		}
	}
	imeiSource := IMEISourceProfile
	modemIMEIErr := error(nil)
	if profile.IMEI == "" {
		if imei, attempted, err := accessIMEIForIMSI(in.Access, profile.IMSI); err == nil && imei != "" {
			profile.IMEI = imei
			imeiSource = IMEISourceModem
			fallbacks = append(fallbacks, NewReadFallbackMetadata(
				IdentityFieldIMEI,
				IMEISourceProfile,
				IMEISourceModem,
				profileIMEIReason,
			))
		} else if attempted {
			modemIMEIErr = err
		}
	}
	if profile.IMEI == "" {
		if imei := normalizeProfileIMEI(in.DeviceID, profile.IMSI); imei != "" {
			profile.IMEI = imei
			imeiSource = IMEISourceDeviceID
			reason := profileIMEIReason
			primary := IMEISourceProfile
			if modemIMEIErr != nil {
				reason = fmt.Errorf("modem IMEI unavailable: %w", modemIMEIErr)
				primary = IMEISourceModem
			}
			fallbacks = append(fallbacks, NewReadFallbackMetadata(
				IdentityFieldIMEI,
				primary,
				IMEISourceDeviceID,
				reason,
			))
		} else {
			imeiSource = IMEISourceUnavailable
			reason := fmt.Errorf("%w and device ID fallback is unavailable", profileIMEIReason)
			if rawProfileIMEI == "" {
				reason = errors.New("profile IMEI is empty and device ID fallback is unavailable")
			}
			primary := IMEISourceProfile
			if modemIMEIErr != nil {
				reason = fmt.Errorf("modem IMEI unavailable and device ID fallback is unavailable: %w", modemIMEIErr)
				primary = IMEISourceModem
			}
			fallbacks = append(fallbacks, NewReadFallbackMetadata(
				IdentityFieldIMEI,
				primary,
				"",
				reason,
			))
		}
	}
	prepared := PreparedSession{
		Profile: profile,
		EffectiveCarrier: EffectiveCarrier{
			MCC:      effectiveCfg.MCC,
			MNC:      effectiveCfg.MNC,
			PresetID: effectiveCfg.PresetID,
		},
		CarrierPolicy:      policy,
		EPDGAddr:           strings.TrimSpace(policy.IMS.EPDGFQDN),
		PCSCFFQDNs:         append([]string(nil), policy.IMS.PCSCFFQDNs...),
		EPDGSource:         "derived",
		IdentityIMSISource: IMSISourceProfile,
		IdentityIMEISource: imeiSource,
		IMSIdentity: IMSIdentityResolution{
			RequestedSource:  IMSIdentitySourceProfile,
			ActualSource:     IMSIdentitySourceProfile,
			AKAAppPreference: AKAAppPreferenceUSIM,
			Applied:          true,
			IMPI:             strings.TrimSpace(policy.IMS.IMSPrivateIdentity),
			IMPU:             strings.TrimSpace(policy.IMS.IMSPublicIdentity),
			Domain:           strings.TrimSpace(policy.IMS.IMSRealm),
		},
		Fallbacks: fallbacks,
	}
	if override := strings.TrimSpace(in.RuntimeEPDGOverride); override != "" {
		prepared.EPDGAddr = override
		prepared.EPDGSource = "redirect"
	}
	if in.Access != nil {
		id, err := in.Access.GetISIMIdentity()
		if err != nil {
			meta := NewReadFallbackMetadata(IdentityFieldIMSIdentity, IMSIdentitySourceISIM, IMSIdentitySourceProfile, err)
			prepared.Fallbacks = append(prepared.Fallbacks, meta)
			prepared.IMSIdentity.RequestedSource = IMSIdentitySourceISIM
			prepared.IMSIdentity.ActualSource = IMSIdentitySourceProfile
			prepared.IMSIdentity.FallbackUsed = true
			prepared.IMSIdentity.FallbackReason = meta.Reason
			prepared.IMSIdentity.RecoveryClass = meta.RecoveryClass
		} else if strings.TrimSpace(id.IMPI) != "" || len(id.IMPU) > 0 || strings.TrimSpace(id.Domain) != "" {
			if strings.TrimSpace(id.IMPI) == "" || len(id.IMPU) == 0 || strings.TrimSpace(id.Domain) == "" {
				return PreparedSession{}, fmt.Errorf("ISIM 身份不完整: impi=%t impu=%d domain=%t",
					strings.TrimSpace(id.IMPI) != "", len(id.IMPU), strings.TrimSpace(id.Domain) != "")
			}
			prepared.IMSIdentity = IMSIdentityResolution{
				RequestedSource:  IMSIdentitySourceISIM,
				ActualSource:     IMSIdentitySourceISIM,
				AKAAppPreference: AKAAppPreferenceISIMStrict,
				Applied:          true,
				IMPI:             strings.TrimSpace(id.IMPI),
				IMPU:             selectISIMIMPU(id.IMPU, id.Domain, profile),
				Domain:           strings.TrimSpace(id.Domain),
			}
		}
	}
	return prepared, nil
}

func accessIMEI(access interface{}) (string, bool, error) {
	return accessIMEIForIMSI(access, "")
}

func accessIMEIForIMSI(access interface{}, imsi string) (string, bool, error) {
	if access == nil {
		return "", false, nil
	}
	reader, ok := access.(interface{ GetIMEI() (string, error) })
	if !ok {
		return "", false, nil
	}
	imei, err := reader.GetIMEI()
	if err != nil {
		return "", true, err
	}
	if imei = normalizeProfileIMEI(imei, imsi); imei != "" {
		return imei, true, nil
	}
	return "", true, errors.New("modem IMEI is empty or invalid")
}

func accessEFAD(access interface{}) ([]byte, error) {
	if access == nil {
		return nil, nil
	}
	reader, ok := access.(interface{ GetEFAD() ([]byte, error) })
	if !ok {
		return nil, nil
	}
	return reader.GetEFAD()
}

func accessSMSC(access interface{}) string {
	if access == nil {
		return ""
	}
	if reader, ok := access.(interface{ GetSMSC() (string, error) }); ok {
		if smsc, err := reader.GetSMSC(); err == nil && strings.TrimSpace(smsc) != "" {
			return strings.TrimSpace(smsc)
		}
	}
	if reader, ok := access.(interface{ QuerySMSC() (string, error) }); ok {
		if smsc, err := reader.QuerySMSC(); err == nil && strings.TrimSpace(smsc) != "" {
			return strings.TrimSpace(smsc)
		}
	}
	return ""
}

// ReadUSIMSMSCCRSM reads the SMSC address from USIM EF_SMSP (0x6F42) via AT+CRSM.
func ReadUSIMSMSCCRSM(access interface {
	ReadCRSMRecord(fileID uint16, record, length int, pathID string) (simtransport.CRSMResult, error)
}, pathID string) (string, error) {
	if access == nil {
		return "", errors.New("nil USIM CRSM access")
	}
	records, resp, err := readCRSMLinearFixedEF(access, 0x6F42, pathID, 4)
	if err != nil {
		return "", classifyCRSMEFReadError("CRSM read EF_SMSP", resp, err)
	}
	var errs []error
	for _, rec := range records {
		smsc, decErr := simauth.DecodeUSIMSMSP(rec)
		if decErr == nil && strings.TrimSpace(smsc) != "" {
			return strings.TrimSpace(smsc), nil
		}
		if decErr != nil {
			errs = append(errs, decErr)
		}
	}
	if len(errs) > 0 {
		return "", errors.Join(errs...)
	}
	return "", errors.New("EF_SMSP has no valid SMSC record")
}

// ComputeIMEILuhn computes the 3GPP TS 23.003 Annex B Luhn check digit for a
// 14-digit TAC+SNR prefix.
func ComputeIMEILuhn(tacSnr14 string) (byte, bool) {
	return simtransport.ComputeIMEILuhn(tacSnr14)
}

// ValidateIMEI reports whether imei15 is a 15-digit IMEI with a valid 3GPP TS
// 23.003 Annex B Luhn check digit.
func ValidateIMEI(imei15 string) bool {
	return simtransport.ValidateIMEI(imei15)
}

func ExtractIMEI(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	if imei := extractGSMAURNIMEI(value); imei != "" {
		return imei
	}
	if imei, ok := simtransport.ExtractIMEI(value); ok {
		return imei
	}
	return ""
}

func extractGSMAURNIMEI(value string) string {
	lower := strings.ToLower(value)
	idx := strings.Index(lower, "urn:gsma:imei:")
	if idx < 0 {
		return ""
	}
	rest := value[idx+len("urn:gsma:imei:"):]
	var digits []byte
	for i := 0; i < len(rest); i++ {
		b := rest[i]
		if b >= '0' && b <= '9' {
			digits = append(digits, b)
			continue
		}
		if b == '-' {
			continue
		}
		break
	}
	s := string(digits)
	switch len(s) {
	case 14, 16:
		if luhn, ok := ComputeIMEILuhn(s[:14]); ok {
			return s[:14] + string(luhn)
		}
	case 15:
		if ValidateIMEI(s) {
			return s
		}
		if s[14] == '0' {
			if luhn, ok := ComputeIMEILuhn(s[:14]); ok {
				return s[:14] + string(luhn)
			}
		}
	}
	return ""
}

func normalizeProfileIMEI(rawIMEI, imsi string) string {
	imei := ExtractIMEI(rawIMEI)
	if imei == "" {
		return ""
	}
	if normalizedIMSI := normalizeIMSI(imsi); normalizedIMSI != "" && imei == normalizedIMSI {
		return ""
	}
	return imei
}

func ValidateIMSIdentityDomain(domain string, network carrier.NetworkConfig, mcc, mnc string) IMSIdentityDomainValidation {
	normalized := normalizeIdentityDomain(domain)
	candidates := carrier.IMSIdentityDomainCandidates(network, mcc, mnc)
	result := IMSIdentityDomainValidation{
		Domain:     normalized,
		Status:     IMSIdentityDomainStatusMismatch,
		Candidates: append([]carrier.IMSIdentityDomainCandidate(nil), candidates...),
	}
	if normalized == "" {
		result.Status = IMSIdentityDomainStatusMissing
		return result
	}
	if len(candidates) == 0 {
		result.Status = IMSIdentityDomainStatusUnknown
		return result
	}
	for _, candidate := range candidates {
		if strings.EqualFold(normalized, candidate.Domain) {
			result.Status = IMSIdentityDomainStatusMatch
			result.MatchedDomain = candidate.Domain
			result.MatchedRole = candidate.Role
			return result
		}
	}
	return result
}

func prepareProfile(p Profile) (Profile, []FallbackMetadata, error) {
	return prepareProfileWithAD(p, nil)
}

func prepareProfileWithAD(p Profile, efAD []byte) (Profile, []FallbackMetadata, error) {
	profile := Profile{
		IMSI:      strings.TrimSpace(p.IMSI),
		MCC:       strings.TrimSpace(p.MCC),
		MNC:       strings.TrimSpace(p.MNC),
		IMEI:      strings.TrimSpace(p.IMEI),
		SMSC:      strings.TrimSpace(p.SMSC),
		MNCLength: p.MNCLength,
	}
	if profile.IMSI == "" {
		return Profile{}, nil, errors.New("IMSI is empty")
	}
	if normalized := normalizeIMSI(profile.IMSI); normalized != "" {
		profile.IMSI = normalized
	} else {
		return Profile{}, nil, fmt.Errorf("invalid IMSI %q: must be 5-15 decimal digits", profile.IMSI)
	}
	profile.IMEI = normalizeProfileIMEI(profile.IMEI, profile.IMSI)

	imsiMCC, imsiMNC := plmnFromIMSIWithAD(profile.IMSI, efAD)
	var fallbacks []FallbackMetadata
	mccMismatch := false
	if mcc := normalizeMCC(profile.MCC); mcc == "" {
		fallbacks = append(fallbacks, profilePLMNFallbackMetadata(IdentityFieldMCC, profile.MCC))
		profile.MCC = imsiMCC
	} else if !strings.HasPrefix(profile.IMSI, mcc) {
		mccMismatch = true
		fallbacks = append(fallbacks, profilePLMNMismatchFallbackMetadata(IdentityFieldMCC, profile.MCC))
		profile.MCC = imsiMCC
	} else {
		profile.MCC = mcc
	}
	if mnc := normalizeProfileMNC(profile.MNC); mnc == "" {
		fallbacks = append(fallbacks, profilePLMNFallbackMetadata(IdentityFieldMNC, profile.MNC))
		profile.MNC = imsiMNC
	} else if mccMismatch || !imsiMatchesPLMN(profile.IMSI, profile.MCC, mnc) {
		fallbacks = append(fallbacks, profilePLMNMismatchFallbackMetadata(IdentityFieldMNC, profile.MNC))
		profile.MNC = imsiMNC
	} else {
		profile.MNC = mnc
	}
	return profile, fallbacks, nil
}

func profilePLMNFallbackMetadata(field, value string) FallbackMetadata {
	value = strings.TrimSpace(value)
	reason := fmt.Errorf("profile %s is empty; derived from IMSI", strings.ToUpper(field))
	if value != "" {
		reason = fmt.Errorf("profile %s %q is invalid; derived from IMSI", strings.ToUpper(field), value)
	}
	return NewReadFallbackMetadata(field, IMSISourceProfile, PLMNSourceIMSI, reason)
}

func profilePLMNMismatchFallbackMetadata(field, value string) FallbackMetadata {
	reason := fmt.Errorf("profile %s %q does not match IMSI; derived from IMSI", strings.ToUpper(field), strings.TrimSpace(value))
	return NewReadFallbackMetadata(field, IMSISourceProfile, PLMNSourceIMSI, reason)
}

func imsiMatchesPLMN(imsi, mcc, mnc string) bool {
	imsi = normalizeIMSI(imsi)
	mcc = normalizeMCC(mcc)
	mnc = normalizeProfileMNC(mnc)
	if imsi == "" || mcc == "" || mnc == "" || !strings.HasPrefix(imsi, mcc) {
		return false
	}
	rest := imsi[len(mcc):]
	if strings.HasPrefix(rest, mnc) {
		return true
	}
	if len(mnc) == 3 && mnc[0] == '0' && strings.HasPrefix(rest, mnc[1:]) {
		return true
	}
	return false
}

func normalizeIMSI(imsi string) string {
	imsi = strings.TrimSpace(imsi)
	if len(imsi) < 5 || len(imsi) > 15 || !isDecimalString(imsi) {
		return ""
	}
	return imsi
}

func normalizeMCC(mcc string) string {
	mcc = strings.TrimSpace(mcc)
	if len(mcc) != 3 || !isDecimalString(mcc) {
		return ""
	}
	return mcc
}

func normalizeMNC(mnc string) string {
	mnc = strings.TrimSpace(mnc)
	if !isDecimalString(mnc) {
		return ""
	}
	if len(mnc) == 2 {
		return "0" + mnc
	}
	if len(mnc) != 3 {
		return ""
	}
	return mnc
}

func normalizeProfileMNC(mnc string) string {
	mnc = strings.TrimSpace(mnc)
	if !isDecimalString(mnc) || (len(mnc) != 2 && len(mnc) != 3) {
		return ""
	}
	return mnc
}

func normalizeIdentityDomain(domain string) string {
	domain = strings.ToLower(strings.TrimSpace(domain))
	return strings.TrimSuffix(domain, ".")
}

func plmnFromIMSI(imsi string) (string, string) {
	return plmnFromIMSIWithAD(imsi, nil)
}

func plmnFromIMSIWithAD(imsi string, efAD []byte) (string, string) {
	mcc, rawMNC := carrier.DerivePLMNFromIMSIWithAD(imsi, efAD)
	if mcc == "" || rawMNC == "" {
		return "", ""
	}
	return mcc, normalizeProfileMNC(rawMNC)
}

func isDecimalString(value string) bool {
	if value == "" {
		return false
	}
	for _, r := range value {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

func selectISIMIMPU(impus []string, domain string, profile Profile) string {
	domain = strings.ToLower(strings.TrimSpace(domain))
	var firstSIP, firstAny string
	for _, impu := range impus {
		impu = strings.TrimSpace(impu)
		if impu == "" {
			continue
		}
		if firstAny == "" {
			firstAny = impu
		}
		if isSIPURI(impu) {
			if firstSIP == "" {
				firstSIP = impu
			}
			if domain != "" && strings.EqualFold(sipURIDomain(impu), domain) {
				return impu
			}
		}
	}
	if firstSIP != "" {
		return firstSIP
	}
	if firstAny != "" {
		return firstAny
	}
	return profileIMPU(profile)
}

func isSIPURI(uri string) bool {
	return strings.HasPrefix(strings.ToLower(strings.TrimSpace(uri)), "sip:")
}

func sipURIDomain(uri string) string {
	uri = strings.TrimSpace(uri)
	if !isSIPURI(uri) {
		return ""
	}
	uri = uri[4:]
	if _, host, ok := strings.Cut(uri, "@"); ok {
		uri = host
	}
	if host, _, ok := strings.Cut(uri, ";"); ok {
		uri = host
	}
	if host, _, ok := strings.Cut(uri, ":"); ok {
		uri = host
	}
	return strings.ToLower(strings.TrimSpace(uri))
}

func profileIMPU(profile Profile) string {
	return profileIMPUWithNetwork(profile, profileNetwork(profile))
}

func profileIMPUWithNetwork(profile Profile, network carrier.NetworkConfig) string {
	imsi := normalizeIMSI(profile.IMSI)
	if imsi == "" {
		return ""
	}
	if impu := carrier.DeriveIMSPublicIdentityForNetwork(imsi, network); impu != "" {
		return impu
	}
	return ""
}

func profileIMPI(profile Profile) string {
	return profileIMPIWithNetwork(profile, profileNetwork(profile))
}

func profileIMPIWithNetwork(profile Profile, network carrier.NetworkConfig) string {
	imsi := normalizeIMSI(profile.IMSI)
	if imsi == "" {
		return ""
	}
	if impi := carrier.DeriveIMSPrivateIdentityForNetwork(imsi, network); impi != "" {
		return impi
	}
	return ""
}

func profileDomain(profile Profile) string {
	return profileDomainWithNetwork(profileNetwork(profile))
}

func profileDomainWithNetwork(network carrier.NetworkConfig) string {
	return strings.TrimSpace(network.IMSRealm)
}

func defaultEPDG(p Profile) string {
	return defaultEPDGWithNetwork(profileNetwork(p))
}

func defaultEPDGWithNetwork(network carrier.NetworkConfig) string {
	return strings.TrimSpace(network.EPDGFQDN)
}

func profileNetwork(profile Profile) carrier.NetworkConfig {
	return carrier.ResolveEffectiveCarrierConfig(carrier.EffectiveCarrierConfigInput{
		IMSI: profile.IMSI,
		MCC:  profile.MCC,
		MNC:  profile.MNC,
	}).Network
}

func ReadISIMIdentity(access interface {
	OpenLogicalChannel(aid string) (int, error)
	CloseLogicalChannel(channel int) error
	TransmitAPDU(channel int, hexAPDU string) (string, error)
}) (Identity, error) {
	if access == nil {
		return Identity{}, errors.New("nil ISIM access")
	}
	unlock := simauth.LockLogicalChannel(access)
	defer unlock()

	channel, _, _, err := simauth.OpenLogicalChannelWithAIDFallback(access, "isim", simauth.ISIMAIDPrefix, simauth.ISIMAIDPrefix)
	if err != nil {
		return Identity{}, err
	}
	defer func() { _ = access.CloseLogicalChannel(channel) }()

	var id Identity
	var readErrs []error

	if raw, resp, err := simauth.ReadTransparentEF(access, channel, 0x6F02); err == nil {
		id.IMPI = decodeISIMString(raw)
	} else {
		readErrs = append(readErrs, classifyAPDUEFReadError("read EF_IMPI", resp, err))
	}

	if raw, resp, err := simauth.ReadTransparentEF(access, channel, 0x6F03); err == nil {
		id.Domain = decodeISIMString(raw)
	} else {
		readErrs = append(readErrs, classifyAPDUEFReadError("read EF_DOMAIN", resp, err))
	}

	if records, resp, err := simauth.ReadLinearFixedEF(access, channel, 0x6F04, 16); err == nil {
		for _, rec := range records {
			if impu := decodeISIMString(rec); impu != "" && !containsString(id.IMPU, impu) {
				id.IMPU = append(id.IMPU, impu)
			}
		}
	} else {
		readErrs = append(readErrs, classifyAPDUEFReadError("read EF_IMPU", resp, err))
	}

	if strings.TrimSpace(id.IMPI) != "" || strings.TrimSpace(id.Domain) != "" || len(id.IMPU) > 0 {
		return id, nil
	}
	return Identity{}, emptyISIMIdentityError(readErrs)
}

func ReadISIMIdentityCRSM(access interface {
	ReadCRSMBinary(fileID uint16, offset, length int, pathID string) (simtransport.CRSMResult, error)
	ReadCRSMRecord(fileID uint16, record, length int, pathID string) (simtransport.CRSMResult, error)
}, pathID string) (Identity, error) {
	if access == nil {
		return Identity{}, errors.New("nil ISIM CRSM access")
	}
	var id Identity
	var readErrs []error

	if raw, resp, err := readCRSMTransparentEF(access, 0x6F02, pathID); err == nil {
		id.IMPI = decodeISIMString(raw)
	} else {
		readErrs = append(readErrs, classifyCRSMEFReadError("CRSM read EF_IMPI", resp, err))
	}
	if raw, resp, err := readCRSMTransparentEF(access, 0x6F03, pathID); err == nil {
		id.Domain = decodeISIMString(raw)
	} else {
		readErrs = append(readErrs, classifyCRSMEFReadError("CRSM read EF_DOMAIN", resp, err))
	}
	if records, resp, err := readCRSMLinearFixedEF(access, 0x6F04, pathID, 16); err == nil {
		for _, rec := range records {
			if impu := decodeISIMString(rec); impu != "" && !containsString(id.IMPU, impu) {
				id.IMPU = append(id.IMPU, impu)
			}
		}
	} else {
		readErrs = append(readErrs, classifyCRSMEFReadError("CRSM read EF_IMPU", resp, err))
	}

	if strings.TrimSpace(id.IMPI) != "" || strings.TrimSpace(id.Domain) != "" || len(id.IMPU) > 0 {
		return id, nil
	}
	return Identity{}, emptyISIMIdentityError(readErrs)
}

func emptyISIMIdentityError(readErrs []error) error {
	if err := errors.Join(readErrs...); err != nil {
		return newISIMIdentityReadError(simtransport.ClassifyError(err), err)
	}
	return newISIMIdentityReadError(simtransport.RecoveryClassEmptyEF, ErrISIMIdentityDataEmpty)
}

func classifyAPDUEFReadError(context string, resp simauth.Response, err error) error {
	if err == nil {
		return nil
	}
	class := simtransport.StatusRecoveryClass(resp.SW1, resp.SW2)
	return newClassifiedReadError(class, fmt.Errorf("%s: %w", context, err))
}

func classifyCRSMEFReadError(context string, resp simtransport.CRSMResult, err error) error {
	if err == nil {
		return nil
	}
	return newClassifiedReadError(resp.RecoveryClass(), fmt.Errorf("%s: %w", context, err))
}

func readCRSMTransparentEF(access interface {
	ReadCRSMBinary(fileID uint16, offset, length int, pathID string) (simtransport.CRSMResult, error)
}, fid uint16, pathID string) ([]byte, simtransport.CRSMResult, error) {
	const maxTransparentEFBytes = 4096
	var out []byte
	var firstResp simtransport.CRSMResult
	for offset := 0; offset < maxTransparentEFBytes; {
		chunk := maxTransparentEFBytes - offset
		if chunk > 256 {
			chunk = 256
		}
		resp, err := access.ReadCRSMBinary(fid, offset, chunk, pathID)
		if offset == 0 {
			firstResp = resp
		}
		if err != nil {
			return nil, resp, err
		}
		raw, decodeErr := decodeCRSMHex(resp.Data)
		eofWarning := resp.SW1 == 0x62 && resp.SW2 == 0x82
		offsetEOF := offset > 0 && (resp.Status() == 0x6B00 || (eofWarning && len(raw) == 0))
		if offsetEOF {
			break
		}
		if !resp.Success() && !(eofWarning && decodeErr == nil && (len(raw) > 0 || len(out) > 0)) {
			return nil, resp, fmt.Errorf("READ BINARY %04X failed: SW=%s", fid, resp.StatusString())
		}
		if decodeErr != nil {
			return nil, resp, decodeErr
		}
		out = append(out, raw...)
		if eofWarning || len(raw) < chunk {
			break
		}
		offset += len(raw)
	}
	return out, firstResp, nil
}

func readCRSMLinearFixedEF(access interface {
	ReadCRSMRecord(fileID uint16, record, length int, pathID string) (simtransport.CRSMResult, error)
}, fid uint16, pathID string, maxRecords int) ([][]byte, simtransport.CRSMResult, error) {
	if maxRecords <= 0 {
		maxRecords = 16
	}
	var records [][]byte
	var last simtransport.CRSMResult
	for rec := 1; rec <= maxRecords; rec++ {
		resp, err := access.ReadCRSMRecord(fid, rec, 256, pathID)
		last = resp
		if err != nil {
			return nil, resp, err
		}
		if isCRSMRecordNotFound(resp.SW1, resp.SW2) {
			break
		}
		if !resp.Success() {
			return nil, resp, fmt.Errorf("READ RECORD %04X #%d failed: SW=%s", fid, rec, resp.StatusString())
		}
		raw, err := decodeCRSMHex(resp.Data)
		if err != nil {
			return nil, resp, err
		}
		if len(raw) == 0 {
			break
		}
		records = append(records, raw)
	}
	return records, last, nil
}

func decodeCRSMHex(data string) ([]byte, error) {
	if strings.TrimSpace(data) == "" {
		return nil, nil
	}
	raw, err := hex.DecodeString(strings.TrimSpace(data))
	if err != nil {
		return nil, fmt.Errorf("decode CRSM data: %w", err)
	}
	return raw, nil
}

func isCRSMRecordNotFound(sw1, sw2 byte) bool {
	return (sw1 == 0x6A && (sw2 == 0x82 || sw2 == 0x83)) ||
		(sw2 == 0x6A && (sw1 == 0x82 || sw1 == 0x83))
}

func decodeISIMString(raw []byte) string {
	return simauth.DecodeISIMIdentityString(raw)
}

func containsString(items []string, want string) bool {
	for _, item := range items {
		if item == want {
			return true
		}
	}
	return false
}
