package ikev2

import (
	"crypto/sha1"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"time"
)

const (
	ProtocolIKE uint8 = 1
	ProtocolAH  uint8 = 2
	ProtocolESP uint8 = 3
)

const (
	NotifyUnsupportedCriticalPayload uint16 = 1
	NotifyInvalidIKESPI              uint16 = 4
	NotifyInvalidMajorVersion        uint16 = 5
	NotifyInvalidSyntax              uint16 = 7
	NotifyInvalidMessageID           uint16 = 9
	NotifyInvalidSPI                 uint16 = 11
	NotifyNoProposalChosen           uint16 = 14
	NotifyInvalidKEPayload           uint16 = 17
	NotifyAuthenticationFailed       uint16 = 24
	NotifySinglePairRequired         uint16 = 34
	NotifyNoAdditionalSAs            uint16 = 35
	NotifyInternalAddressFailure     uint16 = 36
	NotifyFailedCPRequired           uint16 = 37
	NotifyTSUnacceptable             uint16 = 38
	NotifyInvalidSelectors           uint16 = 39
	NotifyUnacceptableAddresses      uint16 = 40
	NotifyUnexpectedNATDetected      uint16 = 41
	NotifyTemporaryFailure           uint16 = 43
	NotifyChildSANotFound            uint16 = 44
	Notify3GPPRATDisallowed          uint16 = 9001
	Notify3GPPNoAPNSubscription      uint16 = 9002
	Notify3GPPNetworkFailure         uint16 = 10500
	Notify3GPPCongestion             uint16 = 15500
	NotifyNATDetectionSourceIP       uint16 = 16388
	NotifyNATDetectionDestinationIP  uint16 = 16389
	NotifyCookie                     uint16 = 16390
	NotifyRekeySA                    uint16 = 16393
	NotifyMOBIKESupported            uint16 = 16396
	NotifyAdditionalIPv4Address      uint16 = 16397
	NotifyAdditionalIPv6Address      uint16 = 16398
	NotifyNoAdditionalAddresses      uint16 = 16399
	NotifyUpdateSAAddresses          uint16 = 16400
	NotifyCookie2                    uint16 = 16401
	NotifyNoNATsAllowed              uint16 = 16402
	NotifyEAPOnlyAuthentication      uint16 = 16417
	NotifyFragmentationSupported     uint16 = 16430
	NotifySignatureHashAlgorithms    uint16 = 16431
	Notify3GPPBackoffTimer           uint16 = 41041
)

const (
	SigHashSHA1     uint16 = 1
	SigHashSHA2_256 uint16 = 2
	SigHashSHA2_384 uint16 = 3
	SigHashSHA2_512 uint16 = 4
)

const (
	MaxIKECookieLength        = 64
	DHGroup2048BitMODP uint16 = 14
	DHGroup256BitECP   uint16 = 19
	DHGroup384BitECP   uint16 = 20
	DHGroup521BitECP   uint16 = 21
	DHGroupCurve25519  uint16 = 31
)

var (
	ErrInvalidNotify                    = errors.New("invalid ikev2 notify payload")
	ErrIKEv2NotifyError                 = errors.New("ikev2 notify error")
	ErrNotifyUnsupportedCriticalPayload = errors.New("ikev2 unsupported critical payload notify")
	ErrNotifyInvalidIKESPI              = errors.New("ikev2 invalid ike spi notify")
	ErrNotifyInvalidMajorVersion        = errors.New("ikev2 invalid major version notify")
	ErrNotifyInvalidSyntax              = errors.New("ikev2 invalid syntax notify")
	ErrNotifyInvalidMessageID           = errors.New("ikev2 invalid message id notify")
	ErrNotifyInvalidSPI                 = errors.New("ikev2 invalid spi notify")
	ErrNotifyNoProposalChosen           = errors.New("ikev2 no proposal chosen notify")
	ErrNotifyInvalidKEPayload           = errors.New("ikev2 invalid ke payload notify")
	ErrNotifyAuthenticationFailed       = errors.New("ikev2 authentication failed notify")
	ErrNotifySinglePairRequired         = errors.New("ikev2 single pair required notify")
	ErrNotifyNoAdditionalSAs            = errors.New("ikev2 no additional sas notify")
	ErrNotifyInternalAddressFailure     = errors.New("ikev2 internal address failure notify")
	ErrNotifyFailedCPRequired           = errors.New("ikev2 failed cp required notify")
	ErrNotifyTSUnacceptable             = errors.New("ikev2 ts unacceptable notify")
	ErrNotifyInvalidSelectors           = errors.New("ikev2 invalid selectors notify")
	ErrNotifyUnacceptableAddresses      = errors.New("ikev2 unacceptable addresses notify")
	ErrNotifyUnexpectedNATDetected      = errors.New("ikev2 unexpected nat detected notify")
	ErrNotifyTemporaryFailure           = errors.New("ikev2 temporary failure notify")
	ErrNotifyChildSANotFound            = errors.New("ikev2 child sa not found notify")
	ErrNotify3GPPRATDisallowed          = errors.New("ikev2 3gpp rat disallowed notify")
	ErrNotify3GPPNoAPNSubscription      = errors.New("ikev2 3gpp no apn subscription notify")
	ErrNotify3GPPNetworkFailure         = errors.New("ikev2 3gpp network failure notify")
	ErrNotify3GPPCongestion             = errors.New("ikev2 3gpp congestion notify")
	ErrInvalidDelete                    = errors.New("invalid ikev2 delete payload")
	ErrInvalidAddress                   = errors.New("invalid ikev2 address")
)

type Notify struct {
	ProtocolID       uint8
	NotifyType       uint16
	SPI              []byte
	NotificationData []byte
}

type InvalidSelectorReport struct {
	ProtocolID   uint8
	SPI          []byte
	PacketPrefix []byte
}

type NotifyError struct {
	Notify          Notify
	Err             error
	BackoffDuration time.Duration
}

func (e *NotifyError) Error() string {
	if e == nil {
		return "<nil>"
	}
	return fmt.Sprintf("%s: %s", ErrIKEv2NotifyError, NotifyTypeName(e.Notify.NotifyType))
}

func (e *NotifyError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Err
}

func (e *NotifyError) Is(target error) bool {
	return target == ErrIKEv2NotifyError || target == e.Err
}

// InvalidKEPayloadAlternativeGroup returns the responder's suggested DH group
// when this notification is INVALID_KE_PAYLOAD.
func (n Notify) InvalidKEPayloadAlternativeGroup() (uint16, bool, error) {
	if n.NotifyType != NotifyInvalidKEPayload {
		return 0, false, nil
	}
	if len(n.NotificationData) != 2 {
		return 0, true, fmt.Errorf("%w: INVALID_KE_PAYLOAD alternative group length %d", ErrInvalidNotify, len(n.NotificationData))
	}
	return binary.BigEndian.Uint16(n.NotificationData), true, nil
}

// InvalidKEPayloadAlternativeGroup returns the suggested DH group carried by an
// INVALID_KE_PAYLOAD notify error.
func (e *NotifyError) InvalidKEPayloadAlternativeGroup() (uint16, bool, error) {
	if e == nil {
		return 0, false, nil
	}
	return e.Notify.InvalidKEPayloadAlternativeGroup()
}

// InvalidKEPayloadAlternativeGroupFromError extracts an INVALID_KE_PAYLOAD
// suggested DH group from a wrapped NotifyError.
func InvalidKEPayloadAlternativeGroupFromError(err error) (uint16, bool, error) {
	if err == nil {
		return 0, false, nil
	}
	var notifyErr *NotifyError
	if !errors.As(err, &notifyErr) {
		return 0, false, nil
	}
	return notifyErr.InvalidKEPayloadAlternativeGroup()
}

func (n Notify) InvalidSelectorReport() (InvalidSelectorReport, bool, error) {
	if n.NotifyType != NotifyInvalidSelectors {
		return InvalidSelectorReport{}, false, nil
	}
	if n.ProtocolID != ProtocolAH && n.ProtocolID != ProtocolESP {
		return InvalidSelectorReport{}, true, fmt.Errorf("%w: INVALID_SELECTORS protocol %d", ErrInvalidNotify, n.ProtocolID)
	}
	if len(n.SPI) != 4 {
		return InvalidSelectorReport{}, true, fmt.Errorf("%w: INVALID_SELECTORS spi length %d", ErrInvalidNotify, len(n.SPI))
	}
	if len(n.NotificationData) == 0 {
		return InvalidSelectorReport{}, true, fmt.Errorf("%w: INVALID_SELECTORS missing packet prefix", ErrInvalidNotify)
	}
	return InvalidSelectorReport{
		ProtocolID:   n.ProtocolID,
		SPI:          append([]byte(nil), n.SPI...),
		PacketPrefix: append([]byte(nil), n.NotificationData...),
	}, true, nil
}

func (e *NotifyError) InvalidSelectorReport() (InvalidSelectorReport, bool, error) {
	if e == nil {
		return InvalidSelectorReport{}, false, nil
	}
	return e.Notify.InvalidSelectorReport()
}

func InvalidSelectorReportFromError(err error) (InvalidSelectorReport, bool, error) {
	if err == nil {
		return InvalidSelectorReport{}, false, nil
	}
	var notifyErr *NotifyError
	if !errors.As(err, &notifyErr) {
		return InvalidSelectorReport{}, false, nil
	}
	return notifyErr.InvalidSelectorReport()
}

func (n Notify) Cookie() ([]byte, bool, error) {
	if n.NotifyType != NotifyCookie {
		return nil, false, nil
	}
	if len(n.SPI) != 0 {
		return nil, true, fmt.Errorf("%w: COOKIE spi length %d", ErrInvalidNotify, len(n.SPI))
	}
	if len(n.NotificationData) == 0 || len(n.NotificationData) > MaxIKECookieLength {
		return nil, true, fmt.Errorf("%w: COOKIE length %d", ErrInvalidNotify, len(n.NotificationData))
	}
	return append([]byte(nil), n.NotificationData...), true, nil
}

func (n Notify) MarshalBinary() ([]byte, error) {
	if len(n.SPI) > 0xff {
		return nil, fmt.Errorf("%w: spi too long", ErrInvalidNotify)
	}
	out := make([]byte, 4, 4+len(n.SPI)+len(n.NotificationData))
	out[0] = n.ProtocolID
	out[1] = byte(len(n.SPI))
	binary.BigEndian.PutUint16(out[2:4], n.NotifyType)
	out = append(out, n.SPI...)
	out = append(out, n.NotificationData...)
	return out, nil
}

func ParseNotify(data []byte) (Notify, error) {
	if len(data) < 4 {
		return Notify{}, ErrInvalidNotify
	}
	spiSize := int(data[1])
	if len(data) < 4+spiSize {
		return Notify{}, ErrInvalidNotify
	}
	return Notify{
		ProtocolID:       data[0],
		NotifyType:       binary.BigEndian.Uint16(data[2:4]),
		SPI:              append([]byte(nil), data[4:4+spiSize]...),
		NotificationData: append([]byte(nil), data[4+spiSize:]...),
	}, nil
}

func NotifyPayload(n Notify) (Payload, error) {
	body, err := n.MarshalBinary()
	if err != nil {
		return Payload{}, err
	}
	return Payload{Type: PayloadNotify, Body: body}, nil
}

func NotifyErrorFor(n Notify) error {
	err := notifyErrorClass(n.NotifyType)
	if err == nil {
		return nil
	}
	return &NotifyError{Notify: cloneNotify(n), Err: err}
}

func FirstNotifyError(payloads []Payload) error {
	var firstErr *NotifyError
	var backoff time.Duration
	for _, payload := range payloads {
		if payload.Type != PayloadNotify {
			continue
		}
		notify, err := ParseNotify(payload.Body)
		if err != nil {
			return err
		}
		if d, ok, bErr := notify.BackoffTimer(); bErr == nil && ok {
			backoff = d
		}
		if firstErr == nil {
			if err := NotifyErrorFor(notify); err != nil {
				var ne *NotifyError
				if errors.As(err, &ne) {
					firstErr = ne
				} else {
					return err
				}
			}
		}
	}
	if firstErr != nil {
		firstErr.BackoffDuration = backoff
		return firstErr
	}
	return nil
}

// ParseGPRSTimer3 decodes a 3GPP TS 24.008 Table 10.5.163 GPRS Timer 3 value
// carried in a 3GPP TS 24.302 §8.2.9.1 BACKOFF_TIMER (41041) notification.
func ParseGPRSTimer3(data []byte) (time.Duration, error) {
	var octet byte
	switch len(data) {
	case 1:
		octet = data[0]
	case 2:
		if data[0] != 1 {
			return 0, fmt.Errorf("%w: BACKOFF_TIMER length byte %d != 1", ErrInvalidNotify, data[0])
		}
		octet = data[1]
	default:
		return 0, fmt.Errorf("%w: BACKOFF_TIMER data length %d", ErrInvalidNotify, len(data))
	}
	unit := (octet >> 5) & 0x07
	value := time.Duration(octet & 0x1f)
	switch unit {
	case 0x00:
		return value * 10 * time.Minute, nil
	case 0x01:
		return value * time.Hour, nil
	case 0x02:
		return value * 10 * time.Hour, nil
	case 0x03:
		return value * 2 * time.Second, nil
	case 0x04:
		return value * 30 * time.Second, nil
	case 0x05:
		return value * time.Minute, nil
	case 0x06:
		return value * 320 * time.Hour, nil
	case 0x07:
		return 0, nil
	default:
		return 0, nil
	}
}

func (n Notify) BackoffTimer() (time.Duration, bool, error) {
	if n.NotifyType != Notify3GPPBackoffTimer {
		return 0, false, nil
	}
	d, err := ParseGPRSTimer3(n.NotificationData)
	if err != nil {
		return 0, true, err
	}
	return d, true, nil
}

func BackoffDurationFromError(err error) (time.Duration, bool) {
	if err == nil {
		return 0, false
	}
	var notifyErr *NotifyError
	if !errors.As(err, &notifyErr) || notifyErr.BackoffDuration <= 0 {
		return 0, false
	}
	return notifyErr.BackoffDuration, true
}

func NotifyTypeName(notifyType uint16) string {
	switch notifyType {
	case NotifyUnsupportedCriticalPayload:
		return "UNSUPPORTED_CRITICAL_PAYLOAD"
	case NotifyInvalidIKESPI:
		return "INVALID_IKE_SPI"
	case NotifyInvalidMajorVersion:
		return "INVALID_MAJOR_VERSION"
	case NotifyInvalidSyntax:
		return "INVALID_SYNTAX"
	case NotifyInvalidMessageID:
		return "INVALID_MESSAGE_ID"
	case NotifyInvalidSPI:
		return "INVALID_SPI"
	case NotifyNoProposalChosen:
		return "NO_PROPOSAL_CHOSEN"
	case NotifyInvalidKEPayload:
		return "INVALID_KE_PAYLOAD"
	case NotifyAuthenticationFailed:
		return "AUTHENTICATION_FAILED"
	case NotifySinglePairRequired:
		return "SINGLE_PAIR_REQUIRED"
	case NotifyNoAdditionalSAs:
		return "NO_ADDITIONAL_SAS"
	case NotifyInternalAddressFailure:
		return "INTERNAL_ADDRESS_FAILURE"
	case NotifyFailedCPRequired:
		return "FAILED_CP_REQUIRED"
	case NotifyTSUnacceptable:
		return "TS_UNACCEPTABLE"
	case NotifyInvalidSelectors:
		return "INVALID_SELECTORS"
	case NotifyUnacceptableAddresses:
		return "UNACCEPTABLE_ADDRESSES"
	case NotifyUnexpectedNATDetected:
		return "UNEXPECTED_NAT_DETECTED"
	case NotifyTemporaryFailure:
		return "TEMPORARY_FAILURE"
	case NotifyChildSANotFound:
		return "CHILD_SA_NOT_FOUND"
	case Notify3GPPRATDisallowed:
		return "3GPP_RAT_DISALLOWED"
	case Notify3GPPNoAPNSubscription:
		return "3GPP_NO_APN_SUBSCRIPTION"
	case Notify3GPPNetworkFailure:
		return "3GPP_NETWORK_FAILURE"
	case Notify3GPPCongestion:
		return "3GPP_CONGESTION"
	case NotifyNATDetectionSourceIP:
		return "NAT_DETECTION_SOURCE_IP"
	case NotifyNATDetectionDestinationIP:
		return "NAT_DETECTION_DESTINATION_IP"
	case NotifyCookie:
		return "COOKIE"
	case NotifyRekeySA:
		return "REKEY_SA"
	case NotifyMOBIKESupported:
		return "MOBIKE_SUPPORTED"
	case NotifyAdditionalIPv4Address:
		return "ADDITIONAL_IP4_ADDRESS"
	case NotifyAdditionalIPv6Address:
		return "ADDITIONAL_IP6_ADDRESS"
	case NotifyNoAdditionalAddresses:
		return "NO_ADDITIONAL_ADDRESSES"
	case NotifyUpdateSAAddresses:
		return "UPDATE_SA_ADDRESSES"
	case NotifyCookie2:
		return "COOKIE2"
	case NotifyNoNATsAllowed:
		return "NO_NATS_ALLOWED"
	case NotifyEAPOnlyAuthentication:
		return "EAP_ONLY_AUTHENTICATION"
	case NotifyFragmentationSupported:
		return "IKEV2_FRAGMENTATION_SUPPORTED"
	case NotifySignatureHashAlgorithms:
		return "SIGNATURE_HASH_ALGORITHMS"
	case Notify3GPPBackoffTimer:
		return "3GPP_BACKOFF_TIMER"
	default:
		return fmt.Sprintf("notify %d", notifyType)
	}
}

func notifyErrorClass(notifyType uint16) error {
	switch notifyType {
	case NotifyUnsupportedCriticalPayload:
		return ErrNotifyUnsupportedCriticalPayload
	case NotifyInvalidIKESPI:
		return ErrNotifyInvalidIKESPI
	case NotifyInvalidMajorVersion:
		return ErrNotifyInvalidMajorVersion
	case NotifyInvalidSyntax:
		return ErrNotifyInvalidSyntax
	case NotifyInvalidMessageID:
		return ErrNotifyInvalidMessageID
	case NotifyInvalidSPI:
		return ErrNotifyInvalidSPI
	case NotifyNoProposalChosen:
		return ErrNotifyNoProposalChosen
	case NotifyInvalidKEPayload:
		return ErrNotifyInvalidKEPayload
	case NotifyAuthenticationFailed:
		return ErrNotifyAuthenticationFailed
	case NotifySinglePairRequired:
		return ErrNotifySinglePairRequired
	case NotifyNoAdditionalSAs:
		return ErrNotifyNoAdditionalSAs
	case NotifyInternalAddressFailure:
		return ErrNotifyInternalAddressFailure
	case NotifyFailedCPRequired:
		return ErrNotifyFailedCPRequired
	case NotifyTSUnacceptable:
		return ErrNotifyTSUnacceptable
	case NotifyInvalidSelectors:
		return ErrNotifyInvalidSelectors
	case NotifyUnacceptableAddresses:
		return ErrNotifyUnacceptableAddresses
	case NotifyUnexpectedNATDetected:
		return ErrNotifyUnexpectedNATDetected
	case NotifyTemporaryFailure:
		return ErrNotifyTemporaryFailure
	case NotifyChildSANotFound:
		return ErrNotifyChildSANotFound
	case Notify3GPPRATDisallowed:
		return ErrNotify3GPPRATDisallowed
	case Notify3GPPNoAPNSubscription:
		return ErrNotify3GPPNoAPNSubscription
	case Notify3GPPNetworkFailure:
		return ErrNotify3GPPNetworkFailure
	case Notify3GPPCongestion:
		return ErrNotify3GPPCongestion
	default:
		if notifyType < 16384 {
			return ErrIKEv2NotifyError
		}
		return nil
	}
}

type Delete struct {
	ProtocolID uint8
	SPIs       [][]byte
}

func (d Delete) MarshalBinary() ([]byte, error) {
	if err := validateDelete(d); err != nil {
		return nil, err
	}
	spiSize := 0
	if len(d.SPIs) > 0 {
		spiSize = len(d.SPIs[0])
	}
	out := make([]byte, 4, 4+spiSize*len(d.SPIs))
	out[0] = d.ProtocolID
	out[1] = byte(spiSize)
	binary.BigEndian.PutUint16(out[2:4], uint16(len(d.SPIs)))
	for _, spi := range d.SPIs {
		out = append(out, spi...)
	}
	return out, nil
}

func ParseDelete(data []byte) (Delete, error) {
	if len(data) < 4 {
		return Delete{}, ErrInvalidDelete
	}
	spiSize := int(data[1])
	spiCount := int(binary.BigEndian.Uint16(data[2:4]))
	want := 4 + spiSize*spiCount
	if want != len(data) {
		return Delete{}, fmt.Errorf("%w: length %d != %d", ErrInvalidDelete, len(data), want)
	}
	d := Delete{
		ProtocolID: data[0],
		SPIs:       make([][]byte, 0, spiCount),
	}
	rest := data[4:]
	for i := 0; i < spiCount; i++ {
		d.SPIs = append(d.SPIs, append([]byte(nil), rest[:spiSize]...))
		rest = rest[spiSize:]
	}
	if err := validateDelete(d); err != nil {
		return Delete{}, err
	}
	return d, nil
}

func DeletePayload(d Delete) (Payload, error) {
	body, err := d.MarshalBinary()
	if err != nil {
		return Payload{}, err
	}
	return Payload{Type: PayloadDelete, Body: body}, nil
}

func IKEDeletePayload() Payload {
	return Payload{Type: PayloadDelete, Body: []byte{ProtocolIKE, 0, 0, 0}}
}

func ESPDeletePayload(spis ...[]byte) (Payload, error) {
	copied := make([][]byte, 0, len(spis))
	for _, spi := range spis {
		copied = append(copied, append([]byte(nil), spi...))
	}
	return DeletePayload(Delete{ProtocolID: ProtocolESP, SPIs: copied})
}

func ChildSADeletePayload(child ChildSAResult) (Payload, error) {
	if len(child.LocalSPI) == 0 {
		return Payload{}, fmt.Errorf("%w: missing local child SPI", ErrInvalidDelete)
	}
	return ESPDeletePayload(child.LocalSPI)
}

func TeardownDeletePayloads(child ChildSAResult, includeIKESA bool) ([]Payload, error) {
	var out []Payload
	if len(child.LocalSPI) > 0 {
		payload, err := ChildSADeletePayload(child)
		if err != nil {
			return nil, err
		}
		out = append(out, payload)
	}
	if includeIKESA {
		out = append(out, IKEDeletePayload())
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("%w: no SAs selected", ErrInvalidDelete)
	}
	return out, nil
}

func validateDelete(d Delete) error {
	switch d.ProtocolID {
	case ProtocolIKE:
		if len(d.SPIs) != 0 {
			return fmt.Errorf("%w: IKE delete must not include SPIs", ErrInvalidDelete)
		}
		return nil
	case ProtocolAH, ProtocolESP:
	default:
		return fmt.Errorf("%w: protocol %d", ErrInvalidDelete, d.ProtocolID)
	}
	if len(d.SPIs) == 0 {
		return fmt.Errorf("%w: no SPIs", ErrInvalidDelete)
	}
	if len(d.SPIs) > 0xffff {
		return fmt.Errorf("%w: too many SPIs", ErrInvalidDelete)
	}
	spiSize := len(d.SPIs[0])
	if spiSize != 4 {
		return fmt.Errorf("%w: SPI size %d", ErrInvalidDelete, spiSize)
	}
	for _, spi := range d.SPIs {
		if len(spi) != spiSize {
			return fmt.Errorf("%w: mixed SPI sizes", ErrInvalidDelete)
		}
	}
	return nil
}

type KeyExchange struct {
	DHGroup uint16
	KeyData []byte
}

func (k KeyExchange) MarshalBinary() []byte {
	out := make([]byte, 4, 4+len(k.KeyData))
	binary.BigEndian.PutUint16(out[0:2], k.DHGroup)
	out = append(out, k.KeyData...)
	return out
}

func ParseKeyExchange(data []byte) (KeyExchange, error) {
	if len(data) < 4 {
		return KeyExchange{}, ErrShortPayload
	}
	return KeyExchange{
		DHGroup: binary.BigEndian.Uint16(data[0:2]),
		KeyData: append([]byte(nil), data[4:]...),
	}, nil
}

func KeyExchangePayload(group uint16, keyData []byte) Payload {
	return Payload{Type: PayloadKE, Body: (KeyExchange{DHGroup: group, KeyData: append([]byte(nil), keyData...)}).MarshalBinary()}
}

func NoncePayload(nonce []byte) Payload {
	return Payload{Type: PayloadNonce, Body: append([]byte(nil), nonce...)}
}

func EAPPayload(packet []byte) Payload {
	return Payload{Type: PayloadEAP, Body: append([]byte(nil), packet...)}
}

func NATDetectionHash(spiI, spiR uint64, ip net.IP, port uint16) ([]byte, error) {
	normalized := ip.To4()
	if normalized == nil {
		normalized = ip.To16()
	}
	if normalized == nil {
		return nil, ErrInvalidAddress
	}
	data := make([]byte, 0, 16+len(normalized)+2)
	data = appendUint64(data, spiI)
	data = appendUint64(data, spiR)
	data = append(data, normalized...)
	data = append(data, byte(port>>8), byte(port))
	sum := sha1.Sum(data)
	return sum[:], nil
}

func NATDetectionNotify(notifyType uint16, spiI, spiR uint64, ip net.IP, port uint16) (Payload, error) {
	if notifyType != NotifyNATDetectionSourceIP && notifyType != NotifyNATDetectionDestinationIP {
		return Payload{}, fmt.Errorf("%w: unsupported NAT detection type %d", ErrInvalidNotify, notifyType)
	}
	hash, err := NATDetectionHash(spiI, spiR, ip, port)
	if err != nil {
		return Payload{}, err
	}
	return NotifyPayload(Notify{
		ProtocolID:       ProtocolIKE,
		NotifyType:       notifyType,
		NotificationData: hash,
	})
}

func MOBIKESupportedNotify() Payload {
	body, _ := (Notify{NotifyType: NotifyMOBIKESupported}).MarshalBinary()
	return Payload{Type: PayloadNotify, Body: body}
}

func FragmentationSupportedNotify() Payload {
	body, _ := (Notify{NotifyType: NotifyFragmentationSupported}).MarshalBinary()
	return Payload{Type: PayloadNotify, Body: body}
}

func EAPOnlyAuthenticationNotify() Payload {
	body, _ := (Notify{NotifyType: NotifyEAPOnlyAuthentication}).MarshalBinary()
	return Payload{Type: PayloadNotify, Body: body}
}

func SignatureHashAlgorithmsNotify(hashIDs ...uint16) Payload {
	if len(hashIDs) == 0 {
		hashIDs = []uint16{SigHashSHA2_256, SigHashSHA2_384, SigHashSHA2_512}
	}
	data := make([]byte, 2*len(hashIDs))
	for i, id := range hashIDs {
		binary.BigEndian.PutUint16(data[i*2:(i+1)*2], id)
	}
	body, _ := (Notify{NotifyType: NotifySignatureHashAlgorithms, NotificationData: data}).MarshalBinary()
	return Payload{Type: PayloadNotify, Body: body}
}

func UpdateSAAddressesNotify() Payload {
	body, _ := (Notify{NotifyType: NotifyUpdateSAAddresses}).MarshalBinary()
	return Payload{Type: PayloadNotify, Body: body}
}

func NoAdditionalAddressesNotify() Payload {
	body, _ := (Notify{NotifyType: NotifyNoAdditionalAddresses}).MarshalBinary()
	return Payload{Type: PayloadNotify, Body: body}
}

func AdditionalIPAddressNotify(ip net.IP) (Payload, error) {
	if v4 := ip.To4(); v4 != nil {
		return NotifyWithZeroSPI(NotifyAdditionalIPv4Address, v4), nil
	}
	if v6 := ip.To16(); v6 != nil {
		return NotifyWithZeroSPI(NotifyAdditionalIPv6Address, v6), nil
	}
	return Payload{}, ErrInvalidAddress
}

func Cookie2Notify(cookie []byte) (Payload, error) {
	if len(cookie) < 8 || len(cookie) > 64 {
		return Payload{}, fmt.Errorf("%w: COOKIE2 length %d", ErrInvalidNotify, len(cookie))
	}
	body, err := (Notify{NotifyType: NotifyCookie2, NotificationData: append([]byte(nil), cookie...)}).MarshalBinary()
	if err != nil {
		return Payload{}, err
	}
	return Payload{Type: PayloadNotify, Body: body}, nil
}

func CookieNotify(cookie []byte) (Payload, error) {
	notify := Notify{NotifyType: NotifyCookie, NotificationData: append([]byte(nil), cookie...)}
	if _, _, err := notify.Cookie(); err != nil {
		return Payload{}, err
	}
	body, err := notify.MarshalBinary()
	if err != nil {
		return Payload{}, err
	}
	return Payload{Type: PayloadNotify, Body: body}, nil
}

func NotifyWithZeroSPI(notifyType uint16, data []byte) Payload {
	body, _ := (Notify{NotifyType: notifyType, NotificationData: append([]byte(nil), data...)}).MarshalBinary()
	return Payload{Type: PayloadNotify, Body: body}
}

func FirstNotify(payloads []Payload, notifyType uint16) (Notify, bool, error) {
	for _, payload := range payloads {
		if payload.Type != PayloadNotify {
			continue
		}
		notify, err := ParseNotify(payload.Body)
		if err != nil {
			return Notify{}, false, err
		}
		if notify.NotifyType == notifyType {
			return notify, true, nil
		}
	}
	return Notify{}, false, nil
}

func cloneNotify(n Notify) Notify {
	return Notify{
		ProtocolID:       n.ProtocolID,
		NotifyType:       n.NotifyType,
		SPI:              append([]byte(nil), n.SPI...),
		NotificationData: append([]byte(nil), n.NotificationData...),
	}
}

func appendUint64(dst []byte, v uint64) []byte {
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], v)
	return append(dst, b[:]...)
}
