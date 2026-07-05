package swu

import (
	"context"
	"errors"
	"fmt"
	"io"

	"github.com/iniwex5/vowifi-go/engine/swu/ikev2"
)

var ErrInvalidIKEControl = errors.New("invalid swu ike control")

type IKECloseConfig struct {
	Transport     ikev2.InitTransport
	Init          ikev2.InitResult
	Keys          ikev2.IKEKeys
	ChildSA       ikev2.ChildSAResult
	NextMessageID uint32
	Payloads      []ikev2.Payload
	Random        io.Reader
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
	return func(ctx context.Context) error {
		_, err := ikev2.RunInformationalExchange(ctx, ikev2.InformationalConfig{
			Transport: cfg.Transport,
			Init:      cfg.Init,
			Keys:      cfg.Keys,
			MessageID: cfg.NextMessageID,
			Payloads:  payloads,
			Random:    cfg.Random,
		})
		return err
	}, nil
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
