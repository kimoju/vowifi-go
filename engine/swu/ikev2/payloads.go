package ikev2

import (
	"crypto/sha1"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
)

const (
	ProtocolIKE uint8 = 1
	ProtocolAH  uint8 = 2
	ProtocolESP uint8 = 3
)

const (
	NotifyNATDetectionSourceIP      uint16 = 16388
	NotifyNATDetectionDestinationIP uint16 = 16389
	NotifyMOBIKESupported           uint16 = 16396
	NotifyUpdateSAAddresses         uint16 = 16400
	NotifyCookie2                   uint16 = 16401
)

const (
	DHGroup2048BitMODP uint16 = 14
	DHGroup256BitECP   uint16 = 19
	DHGroup384BitECP   uint16 = 20
	DHGroup521BitECP   uint16 = 21
	DHGroupCurve25519  uint16 = 31
)

var (
	ErrInvalidNotify  = errors.New("invalid ikev2 notify payload")
	ErrInvalidAddress = errors.New("invalid ikev2 address")
)

type Notify struct {
	ProtocolID       uint8
	NotifyType       uint16
	SPI              []byte
	NotificationData []byte
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
	body, _ := (Notify{ProtocolID: ProtocolIKE, NotifyType: NotifyMOBIKESupported}).MarshalBinary()
	return Payload{Type: PayloadNotify, Body: body}
}

func UpdateSAAddressesNotify() Payload {
	body, _ := (Notify{ProtocolID: ProtocolIKE, NotifyType: NotifyUpdateSAAddresses}).MarshalBinary()
	return Payload{Type: PayloadNotify, Body: body}
}

func appendUint64(dst []byte, v uint64) []byte {
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], v)
	return append(dst, b[:]...)
}
