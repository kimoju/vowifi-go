package identity

import (
	"errors"
	"fmt"
	"strings"
)

const (
	IMSIdentitySourceProfile = "profile"
	IMSIdentitySourceISIM    = "isim"

	AKAAppPreferenceUSIM       = "usim"
	AKAAppPreferenceAuto       = "auto"
	AKAAppPreferenceISIM       = "isim"
	AKAAppPreferenceISIMStrict = "isim_strict"
)

type Profile struct {
	IMSI string
	MCC  string
	MNC  string
	IMEI string
	SMSC string
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
}

type EffectiveCarrier struct {
	MCC      string
	MNC      string
	PresetID string
}

type PreparedSession struct {
	Profile            Profile
	EffectiveCarrier   EffectiveCarrier
	EPDGAddr           string
	EPDGSource         string
	IdentityIMEISource string
	IMSIdentity        IMSIdentityResolution
}

type PrepareStartInput struct {
	DeviceID            string
	Profile             Profile
	RuntimeEPDGOverride string
	Access              interface {
		GetISIMIdentity() (Identity, error)
	}
}

func NormalizeProfile(p Profile) Profile {
	p.IMSI = strings.TrimSpace(p.IMSI)
	p.MCC = strings.TrimSpace(p.MCC)
	p.MNC = strings.TrimSpace(p.MNC)
	p.IMEI = strings.TrimSpace(p.IMEI)
	p.SMSC = strings.TrimSpace(p.SMSC)
	if p.MCC == "" && len(p.IMSI) >= 3 {
		p.MCC = p.IMSI[:3]
	}
	if p.MNC == "" && len(p.IMSI) >= 6 {
		p.MNC = p.IMSI[3:6]
	}
	p.MNC = strings.TrimLeft(p.MNC, "0")
	if p.MNC == "" && len(p.IMSI) >= 6 {
		p.MNC = p.IMSI[3:6]
	}
	return p
}

func PrepareStart(in PrepareStartInput) (PreparedSession, error) {
	profile := NormalizeProfile(in.Profile)
	if profile.IMSI == "" {
		return PreparedSession{}, errors.New("IMSI is empty")
	}
	prepared := PreparedSession{
		Profile: profile,
		EffectiveCarrier: EffectiveCarrier{
			MCC:      profile.MCC,
			MNC:      profile.MNC,
			PresetID: profile.MCC + profile.MNC,
		},
		EPDGAddr:           defaultEPDG(profile),
		EPDGSource:         "derived",
		IdentityIMEISource: "profile",
		IMSIdentity: IMSIdentityResolution{
			RequestedSource:  IMSIdentitySourceProfile,
			ActualSource:     IMSIdentitySourceProfile,
			AKAAppPreference: AKAAppPreferenceUSIM,
			Applied:          true,
			IMPI:             profile.IMSI,
			IMPU:             "sip:" + profile.IMSI,
			Domain:           "",
		},
	}
	if override := strings.TrimSpace(in.RuntimeEPDGOverride); override != "" {
		prepared.EPDGAddr = override
		prepared.EPDGSource = "redirect"
	}
	if in.Access != nil {
		id, err := in.Access.GetISIMIdentity()
		if err == nil && (strings.TrimSpace(id.IMPI) != "" || len(id.IMPU) > 0 || strings.TrimSpace(id.Domain) != "") {
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
				IMPU:             strings.TrimSpace(id.IMPU[0]),
				Domain:           strings.TrimSpace(id.Domain),
			}
		}
	}
	return prepared, nil
}

func defaultEPDG(p Profile) string {
	mcc, mnc := strings.TrimSpace(p.MCC), strings.TrimSpace(p.MNC)
	if mcc == "" || mnc == "" {
		return ""
	}
	return fmt.Sprintf("epdg.epc.mnc%s.mcc%s.pub.3gppnetwork.org", leftPad(mnc, 3), mcc)
}

func leftPad(s string, n int) string {
	for len(s) < n {
		s = "0" + s
	}
	return s
}

func ReadISIMIdentity(access interface {
	OpenLogicalChannel(aid string) (int, error)
	CloseLogicalChannel(channel int) error
	TransmitAPDU(channel int, hexAPDU string) (string, error)
}) (Identity, error) {
	return Identity{}, errors.New("ISIM EF reader is not implemented")
}
