package identity

import (
	"errors"

	"github.com/boa-z/vowifi-go/runtimehost/simtransport"
)

var ErrISIMIdentityDataEmpty = errors.New("ISIM identity data empty")

type ISIMIdentityReadError struct {
	Class simtransport.RecoveryClass
	Err   error
}

func (e *ISIMIdentityReadError) Error() string {
	if e == nil || e.Err == nil {
		return ErrISIMIdentityDataEmpty.Error()
	}
	return e.Err.Error()
}

func (e *ISIMIdentityReadError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Err
}

func (e *ISIMIdentityReadError) RecoveryClass() simtransport.RecoveryClass {
	if e == nil {
		return simtransport.RecoveryClassNone
	}
	return e.Class
}

func IsISIMIdentityDataEmpty(err error) bool {
	return errors.Is(err, ErrISIMIdentityDataEmpty)
}

func newISIMIdentityReadError(class simtransport.RecoveryClass, err error) error {
	if err == nil {
		err = ErrISIMIdentityDataEmpty
	}
	if class == simtransport.RecoveryClassNone {
		class = simtransport.ClassifyError(err)
	}
	return &ISIMIdentityReadError{Class: class, Err: err}
}
