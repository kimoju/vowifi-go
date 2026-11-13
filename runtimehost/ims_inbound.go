package runtimehost

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/kimoju/vowifi-go/runtimehost/voicehost"
)

func startRuntimeIMSInbound(cfg IMSInboundConfig, inst *Instance) (*runtimeIMSInbound, error) {
	if inst == nil {
		return nil, errors.New("runtime instance is nil")
	}
	network := strings.ToLower(strings.TrimSpace(cfg.Network))
	if network == "" {
		network = "udp"
	}
	address := strings.TrimSpace(cfg.LocalAddr)
	if address == "" {
		return nil, errors.New("IMS inbound local address is empty")
	}

	inst.mu.RLock()
	inboundVoice := inst.inboundVoice
	inst.mu.RUnlock()

	contactURI := strings.TrimSpace(cfg.ContactURI)
	if inboundVoice != nil && contactURI != "" {
		inboundVoice.UpdateLocalContact(contactURI)
		contactURI = ""
	}
	server := &voicehost.IMSInboundWireServer{
		Agent:                       inboundVoice,
		OutboundDialogHandler:       inst,
		MessageHandler:              inst,
		MessageDeliveryReportSender: inst,
		ResponsePacketHandler:       cfg.ResponsePacketHandler,
		InfoHandler:                 inst,
		ByeHandler:                  inst,
		NotifyHandler:               inst,
		ContactURI:                  contactURI,
		UserAgent:                   strings.TrimSpace(cfg.UserAgent),
	}
	runCtx, cancel := context.WithCancel(context.Background())
	inbound := &runtimeIMSInbound{
		cancel:    cancel,
		done:      make(chan struct{}),
		network:   network,
		localAddr: address,
	}

	var serve func() error
	switch network {
	case "udp", "udp4", "udp6":
		pc, ln, bindErr := bindIMSInboundUDPAndTCP(network, address, cfg.PacketConn)
		if bindErr != nil {
			cancel()
			return nil, bindErr
		}
		inbound.packet = pc
		inbound.listener = ln
		if pc != nil && pc.LocalAddr() != nil {
			inbound.localAddr = pc.LocalAddr().String()
		} else if ln != nil && ln.Addr() != nil {
			inbound.localAddr = ln.Addr().String()
		}
		if binder, ok := cfg.ResponsePacketHandler.(interface{ BindExternalResponseAddr(string) }); ok && pc != nil && pc.LocalAddr() != nil {
			binder.BindExternalResponseAddr(pc.LocalAddr().String())
		}
		serve = func() error { return server.ServePacketAndListener(runCtx, pc, ln) }
	case "tcp", "tcp4", "tcp6":
		ln, err := net.Listen(network, address)
		if err != nil {
			cancel()
			return nil, err
		}
		inbound.listener = ln
		if ln.Addr() != nil {
			inbound.localAddr = ln.Addr().String()
		}
		serve = func() error { return server.ServeListener(runCtx, ln) }
	default:
		cancel()
		return nil, fmt.Errorf("unsupported IMS inbound network %q", network)
	}

	go func() {
		defer close(inbound.done)
		err := serve()
		if err == nil || runCtx.Err() != nil {
			return
		}
		inst.markIMSInboundFailed(err)
	}()
	return inbound, nil
}

func (r *runtimeIMSInbound) close(ctx context.Context) error {
	if r == nil {
		return nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if r.cancel != nil {
		r.cancel()
	}
	var err error
	if r.packet != nil {
		err = errors.Join(err, r.packet.Close())
	}
	if r.listener != nil {
		err = errors.Join(err, r.listener.Close())
	}
	if r.done != nil {
		select {
		case <-r.done:
		case <-ctx.Done():
			err = errors.Join(err, ctx.Err())
		case <-time.After(2 * time.Second):
			err = errors.Join(err, errors.New("IMS inbound listener stop timeout"))
		}
	}
	return err
}

func bindIMSInboundUDPAndTCP(udpNetwork, address string, existing net.PacketConn) (net.PacketConn, net.Listener, error) {
	tcpNetwork := matchingIMSInboundTCPNetwork(udpNetwork)
	if existing != nil {
		if existing.LocalAddr() == nil {
			return existing, nil, nil
		}
		ln, err := net.Listen(tcpNetwork, existing.LocalAddr().String())
		if err != nil {
			if _, isRealUDP := existing.(*net.UDPConn); !isRealUDP {
				return existing, nil, nil
			}
			if strings.Contains(strings.ToLower(err.Error()), "cannot assign requested address") {
				return existing, nil, nil
			}
			_ = existing.Close()
			return nil, nil, err
		}
		return existing, ln, nil
	}

	_, requestedPort, _ := net.SplitHostPort(address)
	ephemeral := requestedPort == "0" || requestedPort == ""
	attempts := 1
	if ephemeral {
		attempts = 8
	}
	var lastErr error
	for i := 0; i < attempts; i++ {
		pc, err := net.ListenPacket(udpNetwork, address)
		if err != nil {
			return nil, nil, err
		}
		tcpAddr := address
		if pc.LocalAddr() != nil {
			tcpAddr = pc.LocalAddr().String()
		}
		ln, tcpErr := net.Listen(tcpNetwork, tcpAddr)
		if tcpErr == nil {
			return pc, ln, nil
		}
		_ = pc.Close()
		lastErr = tcpErr
	}
	return nil, nil, lastErr
}

func matchingIMSInboundTCPNetwork(udpNetwork string) string {
	switch strings.ToLower(strings.TrimSpace(udpNetwork)) {
	case "udp4":
		return "tcp4"
	case "udp6":
		return "tcp6"
	default:
		return "tcp"
	}
}

func (i *Instance) markIMSInboundFailed(err error) {
	if i == nil || err == nil {
		return
	}
	i.mu.Lock()
	if i.stopped {
		i.mu.Unlock()
		return
	}
	i.state.SMSReady = false
	i.state.LastError = err.Error()
	i.state.LastReason = "IMS inbound listener stopped"
	i.state.UpdatedAt = time.Now()
	i.mu.Unlock()
	i.notify(context.Background())
	i.dispatchRuntimeState(context.Background())
}
