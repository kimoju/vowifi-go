package ikev2

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
)

const (
	encryptedFragmentBodyHeaderLength = 4
	MaxEncryptedFragments             = 64
	MaxReassembledEncryptedSize       = 64 * 1024
	DefaultIKEFragmentMTU             = 1280
	MinIKEFragmentMTU                 = 576
)

var ErrInvalidEncryptedFragment = errors.New("invalid ikev2 encrypted fragment payload")

// FragmentInitTransport is an optional extension of InitTransport for transports
// that can transmit multiple SKF request datagrams and read multiple SKF
// response datagrams within a single IKEv2 exchange (RFC 7383).
type FragmentInitTransport interface {
	InitTransport
	ExchangeIKEFragments(ctx context.Context, requests [][]byte, acceptResponse func(raw []byte) (done bool, err error)) error
}

type EncryptedFragment struct {
	FragmentNumber uint16
	TotalFragments uint16
	EncryptedData  []byte
}

func (f EncryptedFragment) MarshalBinary() ([]byte, error) {
	if f.FragmentNumber == 0 {
		return nil, fmt.Errorf("%w: fragment number is zero", ErrInvalidEncryptedFragment)
	}
	if f.TotalFragments == 0 {
		return nil, fmt.Errorf("%w: total fragments is zero", ErrInvalidEncryptedFragment)
	}
	if f.TotalFragments > MaxEncryptedFragments {
		return nil, fmt.Errorf("%w: total fragments %d exceeds maximum %d", ErrInvalidEncryptedFragment, f.TotalFragments, MaxEncryptedFragments)
	}
	if f.FragmentNumber > f.TotalFragments {
		return nil, fmt.Errorf("%w: fragment %d > total %d", ErrInvalidEncryptedFragment, f.FragmentNumber, f.TotalFragments)
	}
	if len(f.EncryptedData) == 0 {
		return nil, fmt.Errorf("%w: encrypted data is empty", ErrInvalidEncryptedFragment)
	}
	if encryptedFragmentBodyHeaderLength+len(f.EncryptedData)+4 > 0xffff {
		return nil, fmt.Errorf("%w: %w: payload length %d", ErrInvalidEncryptedFragment, ErrInvalidLength, encryptedFragmentBodyHeaderLength+len(f.EncryptedData)+4)
	}
	out := make([]byte, encryptedFragmentBodyHeaderLength, encryptedFragmentBodyHeaderLength+len(f.EncryptedData))
	binary.BigEndian.PutUint16(out[0:2], f.FragmentNumber)
	binary.BigEndian.PutUint16(out[2:4], f.TotalFragments)
	out = append(out, f.EncryptedData...)
	return out, nil
}

func ParseEncryptedFragment(data []byte) (EncryptedFragment, error) {
	if len(data) <= encryptedFragmentBodyHeaderLength {
		return EncryptedFragment{}, fmt.Errorf("%w: body length %d", ErrInvalidEncryptedFragment, len(data))
	}
	fragmentNumber := binary.BigEndian.Uint16(data[0:2])
	totalFragments := binary.BigEndian.Uint16(data[2:4])
	if fragmentNumber == 0 {
		return EncryptedFragment{}, fmt.Errorf("%w: fragment number is zero", ErrInvalidEncryptedFragment)
	}
	if totalFragments == 0 {
		return EncryptedFragment{}, fmt.Errorf("%w: total fragments is zero", ErrInvalidEncryptedFragment)
	}
	if totalFragments > MaxEncryptedFragments {
		return EncryptedFragment{}, fmt.Errorf("%w: total fragments %d exceeds maximum %d", ErrInvalidEncryptedFragment, totalFragments, MaxEncryptedFragments)
	}
	if fragmentNumber > totalFragments {
		return EncryptedFragment{}, fmt.Errorf("%w: fragment %d > total %d", ErrInvalidEncryptedFragment, fragmentNumber, totalFragments)
	}
	payload := data[encryptedFragmentBodyHeaderLength:]
	if len(payload) > MaxReassembledEncryptedSize {
		return EncryptedFragment{}, fmt.Errorf("%w: fragment size %d exceeds maximum %d", ErrInvalidEncryptedFragment, len(payload), MaxReassembledEncryptedSize)
	}
	return EncryptedFragment{
		FragmentNumber: fragmentNumber,
		TotalFragments: totalFragments,
		EncryptedData:  append([]byte(nil), payload...),
	}, nil
}

func EncryptedFragmentPayload(nextPayload uint8, fragment EncryptedFragment) (Payload, error) {
	body, err := fragment.MarshalBinary()
	if err != nil {
		return Payload{}, err
	}
	return Payload{Type: PayloadSKF, NextPayload: nextPayload, Body: body}, nil
}

// EncryptedFragmentAssembler bounds fragment count and total reassembled size
// per RFC 7383 to prevent memory exhaustion from SKF payloads. Use
// AddProtectedFragment when processing wire SKF packets so outer MAC/AEAD
// authentication is verified before mutating reassembly state (RFC 7383 §2.6).
type EncryptedFragmentAssembler struct {
	MaxFragments uint16
	MaxSize      int

	total            uint16
	received         int
	totalSize        int
	parts            [][]byte
	hasHeader        bool
	header           Header
	firstMessage     Message
	firstNextPayload uint8
}

func (a *EncryptedFragmentAssembler) Add(fragment EncryptedFragment) ([]byte, bool, error) {
	if fragment.FragmentNumber == 0 || fragment.TotalFragments == 0 || fragment.FragmentNumber > fragment.TotalFragments || len(fragment.EncryptedData) == 0 {
		return nil, false, fmt.Errorf("%w: invalid fragment metadata", ErrInvalidEncryptedFragment)
	}
	return a.addChunk(fragment.FragmentNumber, fragment.TotalFragments, fragment.EncryptedData)
}

func (a *EncryptedFragmentAssembler) addChunk(fragNum, totalFrags uint16, chunk []byte) ([]byte, bool, error) {
	if fragNum == 0 || totalFrags == 0 || fragNum > totalFrags {
		return nil, false, fmt.Errorf("%w: invalid fragment metadata", ErrInvalidEncryptedFragment)
	}
	maxFragments := a.MaxFragments
	if maxFragments == 0 {
		maxFragments = MaxEncryptedFragments
	}
	if totalFrags > maxFragments {
		return nil, false, fmt.Errorf("%w: total fragments %d exceeds maximum %d", ErrInvalidEncryptedFragment, totalFrags, maxFragments)
	}
	maxSize := a.MaxSize
	if maxSize <= 0 {
		maxSize = MaxReassembledEncryptedSize
	}
	if a.total != 0 && totalFrags != a.total {
		return nil, false, fmt.Errorf("%w: total fragments %d != %d", ErrInvalidEncryptedFragment, totalFrags, a.total)
	}
	idx := int(fragNum - 1)
	if a.total != 0 && a.parts[idx] != nil {
		// Ignore duplicate retransmitted fragment per RFC 7383 §2.6.
		return nil, false, nil
	}
	if a.totalSize+len(chunk) > maxSize {
		return nil, false, fmt.Errorf("%w: reassembled size %d exceeds maximum %d", ErrInvalidEncryptedFragment, a.totalSize+len(chunk), maxSize)
	}
	if a.total == 0 {
		a.total = totalFrags
		a.parts = make([][]byte, int(a.total))
	}
	copied := make([]byte, len(chunk))
	copy(copied, chunk)
	a.parts[idx] = copied
	a.totalSize += len(copied)
	a.received++
	if a.received < int(a.total) {
		return nil, false, nil
	}
	out := make([]byte, 0, a.totalSize)
	for _, part := range a.parts {
		out = append(out, part...)
	}
	return out, true, nil
}

// AddProtectedFragment verifies the outer SKF MAC/AEAD tag and decrypts the
// fragment chunk via UnprotectFragment BEFORE mutating reassembly state per
// RFC 7383 §2.6. Once all fragments 1..TotalFragments are authenticated, it
// parses and returns the inner payload chain.
func (a *EncryptedFragmentAssembler) AddProtectedFragment(raw []byte, keys IKEKeys, fromInitiator bool) (Message, []Payload, bool, error) {
	msg, nextPayload, fragNum, totalFrags, plainChunk, err := UnprotectFragment(raw, keys, fromInitiator)
	if err != nil {
		return Message{}, nil, false, err
	}
	if a.hasHeader {
		h := msg.Header
		if h.InitiatorSPI != a.header.InitiatorSPI ||
			h.ResponderSPI != a.header.ResponderSPI ||
			h.ExchangeType != a.header.ExchangeType ||
			h.Flags != a.header.Flags ||
			h.MessageID != a.header.MessageID {
			return Message{}, nil, false, fmt.Errorf("%w: inconsistent fragment IKE header", ErrInvalidEncryptedFragment)
		}
	}
	reassembled, complete, err := a.addChunk(fragNum, totalFrags, plainChunk)
	if err != nil {
		return Message{}, nil, false, err
	}
	if !a.hasHeader {
		a.hasHeader = true
		a.header = msg.Header
		a.firstMessage = msg
	}
	if fragNum == 1 {
		a.firstNextPayload = nextPayload
		a.firstMessage = msg
	}
	if !complete {
		return Message{}, nil, false, nil
	}
	inner, err := ParsePayloads(a.firstNextPayload, reassembled)
	if err != nil {
		return Message{}, nil, false, err
	}
	return a.firstMessage, inner, true, nil
}

func ReassembleEncryptedFragments(fragments []EncryptedFragment) ([]byte, error) {
	if len(fragments) == 0 {
		return nil, fmt.Errorf("%w: no fragments provided", ErrInvalidEncryptedFragment)
	}
	var assembler EncryptedFragmentAssembler
	for _, f := range fragments {
		out, complete, err := assembler.Add(f)
		if err != nil {
			return nil, err
		}
		if complete {
			return out, nil
		}
	}
	return nil, fmt.Errorf("%w: incomplete fragment set (%d/%d)", ErrInvalidEncryptedFragment, assembler.received, assembler.total)
}
