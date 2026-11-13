package swu

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/kimoju/vowifi-go/engine/swu/ikev2"
)

var ErrInvalidIKEControl = errors.New("invalid swu ike control")
var ErrMOBIKEUpdateRejected = errors.New("mobike update rejected")

type localIPRebinder interface {
	RebindLocalIP(ctx context.Context, newLocalIP net.IP) (net.Addr, error)
}

type IKECloseConfig struct {
	Transport     ikev2.InitTransport
	Init          ikev2.InitResult
	Keys          ikev2.IKEKeys
	ChildSA       ikev2.ChildSAResult
	NextMessageID uint32
	Payloads      []ikev2.Payload
	Random        io.Reader
}

type IKEMOBIKEConfig struct {
	Transport             ikev2.InitTransport
	Init                  ikev2.InitResult
	Keys                  ikev2.IKEKeys
	NextMessageID         uint32
	Result                TunnelResult
	LocalIP               net.IP
	RemoteIP              net.IP
	LocalPort             uint16
	RemotePort            uint16
	AdditionalAddresses   []net.IP
	NoAdditionalAddresses bool
	Random                io.Reader
}

func NewIKECloseHandler(cfg IKECloseConfig) (func(context.Context) error, error) {
	if cfg.Transport == nil {
		return nil, fmt.Errorf("%w: transport is nil", ErrInvalidIKEControl)
	}
	if cfg.NextMessageID == 0 {
		return nil, fmt.Errorf("%w: next message_id is zero", ErrInvalidIKEControl)
	}
	payloads := cloneIKEPayloads(cfg.Payloads)
	if len(payloads) == 0 {
		var err error
		payloads, err = ikev2.TeardownDeletePayloads(cfg.ChildSA, true)
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrInvalidIKEControl, err)
		}
	}
	retransmitTransport := newRetransmittingIKETransport(cfg.Transport, defaultIKEControlMaxRetransmits)
	return func(ctx context.Context) error {
		_, err := ikev2.RunInformationalExchange(ctx, ikev2.InformationalConfig{
			Transport: retransmitTransport,
			Init:      cfg.Init,
			Keys:      cfg.Keys,
			MessageID: cfg.NextMessageID,
			Payloads:  payloads,
			Random:    cfg.Random,
		})
		return err
	}, nil
}

func NewIKEMOBIKEHandler(cfg IKEMOBIKEConfig) (func(context.Context, MOBIKERequest) (MOBIKEResult, error), error) {
	if cfg.Transport == nil {
		return nil, fmt.Errorf("%w: transport is nil", ErrInvalidIKEControl)
	}
	if cfg.NextMessageID == 0 {
		return nil, fmt.Errorf("%w: next message_id is zero", ErrInvalidIKEControl)
	}
	additional := cloneIPs(cfg.AdditionalAddresses)
	messageIDs, err := newIKEControlMessageIDs(cfg.NextMessageID)
	if err != nil {
		return nil, err
	}
	var stateMu sync.Mutex
	curLocalIP := normalizedMOBIKEIP(cfg.LocalIP)
	curLocalPort := cfg.LocalPort
	retransmitTransport := newRetransmittingIKETransport(cfg.Transport, defaultIKEControlMaxRetransmits)
	return func(ctx context.Context, req MOBIKERequest) (MOBIKEResult, error) {
		stateMu.Lock()
		localIP := normalizedMOBIKEIP(curLocalIP)
		localPort := curLocalPort
		stateMu.Unlock()

		if newIP := normalizedMOBIKEIP(nil, req.NewIP); newIP != nil {
			if rebinder, ok := cfg.Transport.(localIPRebinder); ok {
				reboundAddr, err := rebinder.RebindLocalIP(ctx, newIP)
				if err != nil {
					return MOBIKEResult{}, err
				}
				localIP = newIP
				if udpAddr, ok := reboundAddr.(*net.UDPAddr); ok && udpAddr.Port > 0 && udpAddr.Port <= 65535 {
					localPort = uint16(udpAddr.Port)
				}
			} else {
				localIP = newIP
			}
		}

		reqCfg := cfg
		reqCfg.LocalIP = localIP
		reqCfg.LocalPort = localPort
		payloads, err := mobikeUpdatePayloads(reqCfg, additional, req)
		if err != nil {
			return MOBIKEResult{}, err
		}
		err = messageIDs.exchange(func(messageID uint32) error {
			res, err := ikev2.RunInformationalExchange(ctx, ikev2.InformationalConfig{
				Transport: retransmitTransport,
				Init:      cfg.Init,
				Keys:      cfg.Keys,
				MessageID: messageID,
				Payloads:  payloads,
				Random:    cfg.Random,
			})
			if err != nil {
				return err
			}
			return rejectMOBIKEResponse(res.ResponseInner)
		})
		if err != nil {
			return MOBIKEResult{}, err
		}
		if localIP != nil {
			stateMu.Lock()
			curLocalIP = append(net.IP(nil), localIP...)
			curLocalPort = localPort
			stateMu.Unlock()
		}
		return MOBIKEResult{
			Rekeyed:          false,
			OuterLocalIP:     firstPacketNonEmpty(req.NewIP, req.OldIP, cfg.Result.EPDGAddress),
			LocalInnerIP:     cfg.Result.LocalInnerIP,
			RemoteInnerIP:    cfg.Result.RemoteInnerIP,
			IKEEstablished:   true,
			IPsecEstablished: true,
			Reason:           "mobike update sa addresses sent",
			UpdatedAt:        time.Now(),
		}, nil
	}, nil
}

type ikeControlMessageIDs struct {
	mu   sync.Mutex
	next uint32
}

func newIKEControlMessageIDs(next uint32) (*ikeControlMessageIDs, error) {
	if next == 0 {
		return nil, fmt.Errorf("%w: next message_id is zero", ErrInvalidIKEControl)
	}
	return &ikeControlMessageIDs{next: next}, nil
}

func (s *ikeControlMessageIDs) exchange(fn func(uint32) error) error {
	if s == nil {
		return fmt.Errorf("%w: message id scheduler is nil", ErrInvalidIKEControl)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.next == 0 {
		return fmt.Errorf("%w: next message_id is zero", ErrInvalidIKEControl)
	}
	messageID := s.next
	s.next++
	return fn(messageID)
}

func cloneIKEPayloads(in []ikev2.Payload) []ikev2.Payload {
	out := make([]ikev2.Payload, len(in))
	for i, p := range in {
		out[i] = ikev2.Payload{
			Type:        p.Type,
			NextPayload: p.NextPayload,
			Critical:    p.Critical,
			Body:        append([]byte(nil), p.Body...),
		}
	}
	return out
}

func mobikeUpdatePayloads(cfg IKEMOBIKEConfig, additional []net.IP, req MOBIKERequest) ([]ikev2.Payload, error) {
	payloads := []ikev2.Payload{ikev2.UpdateSAAddressesNotify()}
	localIP := normalizedMOBIKEIP(nil, req.NewIP, req.OldIP)
	if localIP == nil {
		localIP = normalizedMOBIKEIP(cfg.LocalIP)
	}
	remoteIP := normalizedMOBIKEIP(cfg.RemoteIP)
	if localIP != nil && remoteIP != nil {
		localPort := cfg.LocalPort
		if localPort == 0 {
			localPort = 4500
		}
		remotePort := cfg.RemotePort
		if remotePort == 0 {
			remotePort = 4500
		}
		src, err := ikev2.NATDetectionNotify(ikev2.NotifyNATDetectionSourceIP, cfg.Init.InitiatorSPI, cfg.Init.ResponderSPI, localIP, localPort)
		if err != nil {
			return nil, err
		}
		dst, err := ikev2.NATDetectionNotify(ikev2.NotifyNATDetectionDestinationIP, cfg.Init.InitiatorSPI, cfg.Init.ResponderSPI, remoteIP, remotePort)
		if err != nil {
			return nil, err
		}
		payloads = append(payloads, src, dst)
	}
	for _, ip := range additional {
		payload, err := ikev2.AdditionalIPAddressNotify(ip)
		if err != nil {
			return nil, err
		}
		payloads = append(payloads, payload)
	}
	if cfg.NoAdditionalAddresses {
		payloads = append(payloads, ikev2.NoAdditionalAddressesNotify())
	}
	return payloads, nil
}

func rejectMOBIKEResponse(payloads []ikev2.Payload) error {
	for _, payload := range payloads {
		if payload.Type != ikev2.PayloadNotify {
			continue
		}
		notify, err := ikev2.ParseNotify(payload.Body)
		if err != nil {
			return err
		}
		switch notify.NotifyType {
		case ikev2.NotifyUnacceptableAddresses:
			return fmt.Errorf("%w: unacceptable addresses", ErrMOBIKEUpdateRejected)
		case ikev2.NotifyUnexpectedNATDetected:
			return fmt.Errorf("%w: unexpected NAT detected", ErrMOBIKEUpdateRejected)
		}
	}
	return nil
}

func normalizedMOBIKEIP(primary net.IP, fallbacks ...string) net.IP {
	if primary != nil {
		if ip := primary.To4(); ip != nil {
			return append(net.IP(nil), ip...)
		}
		if ip := primary.To16(); ip != nil {
			return append(net.IP(nil), ip...)
		}
	}
	for _, item := range fallbacks {
		ip := net.ParseIP(firstPacketNonEmpty(item))
		if ip == nil {
			continue
		}
		if v4 := ip.To4(); v4 != nil {
			return append(net.IP(nil), v4...)
		}
		if v6 := ip.To16(); v6 != nil {
			return append(net.IP(nil), v6...)
		}
	}
	return nil
}

func cloneIPs(in []net.IP) []net.IP {
	out := make([]net.IP, 0, len(in))
	for _, ip := range in {
		if normalized := normalizedMOBIKEIP(ip); normalized != nil {
			out = append(out, normalized)
		}
	}
	return out
}

const defaultIKEControlMaxRetransmits = 2

type retransmittingIKETransport struct {
	base           ikev2.InitTransport
	maxRetransmits int
}

func newRetransmittingIKETransport(base ikev2.InitTransport, maxRetransmits int) ikev2.InitTransport {
	if base == nil {
		return nil
	}
	switch base.(type) {
	case *retransmittingIKETransport, ikev2.UDPTransport, *ikev2.UDPTransport, *ikev2.PersistentUDPTransport:
		return base
	}
	if maxRetransmits <= 0 {
		return base
	}
	return &retransmittingIKETransport{base: base, maxRetransmits: maxRetransmits}
}

func (t *retransmittingIKETransport) ExchangeIKE(ctx context.Context, request []byte) ([]byte, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	var lastErr error
	for attempt := 0; attempt <= t.maxRetransmits; attempt++ {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		resp, err := t.base.ExchangeIKE(ctx, request)
		if err == nil {
			return resp, nil
		}
		lastErr = err
		var netErr net.Error
		if !errors.As(err, &netErr) || !netErr.Timeout() || ctx.Err() != nil {
			return nil, err
		}
	}
	return nil, lastErr
}

func (t *retransmittingIKETransport) ExchangeIKEFragments(ctx context.Context, requests [][]byte, acceptResponse func(raw []byte) (done bool, err error)) error {
	fragBase, ok := t.base.(ikev2.FragmentInitTransport)
	if !ok {
		if len(requests) != 1 {
			return fmt.Errorf("%w: underlying transport does not support IKE fragmentation", ErrInvalidIKEControl)
		}
		resp, err := t.ExchangeIKE(ctx, requests[0])
		if err != nil {
			return err
		}
		done, err := acceptResponse(resp)
		if err != nil {
			return err
		}
		if !done {
			return fmt.Errorf("%w: incomplete fragmented IKE response", ErrInvalidIKEControl)
		}
		return nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	var lastErr error
	for attempt := 0; attempt <= t.maxRetransmits; attempt++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		err := fragBase.ExchangeIKEFragments(ctx, requests, acceptResponse)
		if err == nil {
			return nil
		}
		lastErr = err
		var netErr net.Error
		if !errors.As(err, &netErr) || !netErr.Timeout() || ctx.Err() != nil {
			return err
		}
	}
	return lastErr
}

func (t *retransmittingIKETransport) RebindLocalIP(ctx context.Context, newLocalIP net.IP) (net.Addr, error) {
	if rebinder, ok := t.base.(localIPRebinder); ok {
		return rebinder.RebindLocalIP(ctx, newLocalIP)
	}
	return nil, fmt.Errorf("%w: underlying transport does not support local IP rebind", ErrInvalidIKEControl)
}
