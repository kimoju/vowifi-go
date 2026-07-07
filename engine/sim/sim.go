package sim

import "errors"

var (
	ErrSyncFailure = errors.New("aka sync failure")
	ErrAuthFailure = errors.New("aka authentication failure")
)

type AKAResult struct {
	RES  []byte
	CK   []byte
	IK   []byte
	AUTS []byte
}

type SyncFailureError struct {
	auts []byte
}

func NewSyncFailureError(auts []byte) *SyncFailureError {
	return &SyncFailureError{auts: append([]byte(nil), auts...)}
}

func (e *SyncFailureError) Error() string {
	return ErrSyncFailure.Error()
}

func (e *SyncFailureError) Unwrap() error {
	return ErrSyncFailure
}

func (e *SyncFailureError) AUTS() []byte {
	if e == nil {
		return nil
	}
	return append([]byte(nil), e.auts...)
}

type AKAProvider interface {
	CalculateAKA(rand16, autn16 []byte) (AKAResult, error)
}

type ISIMAKAProvider interface {
	CalculateISIMAKA(rand16, autn16 []byte) (AKAResult, error)
}
