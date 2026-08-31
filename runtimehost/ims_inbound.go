package runtimehost

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/boa-z/vowifi-go/runtimehost/voicehost"
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

	server := &voicehost.IMSInboundWireServer{
		MessageHandler:              inst,
		MessageDeliveryReportSender: inst,
		ResponsePacketHandler:       cfg.ResponsePacketHandler,
		InfoHandler:                 inst,
		ByeHandler:                  inst,
		ContactURI:                  strings.TrimSpace(cfg.ContactURI),
		UserAgent:                   strings.TrimSpace(cfg.UserAgent),
	}
	runCtx, cancel := context.WithCancel(context.Background())
	inbound := &runtimeIMSInbound{cancel: cancel, done: make(chan struct{})}

	var serve func() error
	switch network {
	case "udp", "udp4", "udp6":
		pc := cfg.PacketConn
		if pc == nil {
			var err error
			pc, err = net.ListenPacket(network, address)
			if err != nil {
				cancel()
				return nil, err
			}
		}
		inbound.packet = pc
		serve = func() error { return server.ServePacket(runCtx, pc) }
	case "tcp", "tcp4", "tcp6":
		ln, err := net.Listen(network, address)
		if err != nil {
			cancel()
			return nil, err
		}
		inbound.listener = ln
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
