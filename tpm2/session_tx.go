package tpm2

import (
	"errors"
	"fmt"
)

// ErrSessionInvalid indicates that local session bookkeeping can no longer be
// synchronized with the TPM session.
var ErrSessionInvalid = errors.New("session invalid")

// ErrSessionUseExhausted indicates that a session's finite use count has been
// consumed.
var ErrSessionUseExhausted = errors.New("session use count exhausted")

// SessionTransaction represents a pending change to session bookkeeping.
//
// BeginCommand decrements or otherwise reserves a use. Commit makes that change
// permanent after the complete response has been parsed. Rollback restores the
// state that was captured before the command was assembled.
type SessionTransaction interface {
	Commit()
	Rollback()
}

// TransactionalSession is implemented by sessions whose mutable bookkeeping
// must be restored when a command does not complete successfully.
type TransactionalSession interface {
	BeginCommand() (SessionTransaction, error)
}

// InvalidatableSession is implemented by sessions that cannot be assumed to
// still match the TPM after an error with an indeterminate outcome, such as a
// transport timeout or connection failure.
type InvalidatableSession interface {
	InvalidateSession(cause error)
}

// UsageMeter is implemented by sessions that enforce a local use-count budget.
type UsageMeter interface {
	RemainingUses() (remaining int, limited bool)
}

var (
	_ TransactionalSession = (*hmacSession)(nil)
	_ InvalidatableSession = (*hmacSession)(nil)
	_ UsageMeter           = (*hmacSession)(nil)
	_ TransactionalSession = (*policySession)(nil)
	_ InvalidatableSession = (*policySession)(nil)
	_ UsageMeter           = (*policySession)(nil)
)

func beginSessionTransaction(s Session) (SessionTransaction, error) {
	transactional, ok := s.(TransactionalSession)
	if !ok {
		return nil, nil
	}
	tx, err := transactional.BeginCommand()
	if err != nil {
		return nil, err
	}
	return tx, nil
}

func invalidateSession(s Session, cause error) {
	if invalidatable, ok := s.(InvalidatableSession); ok {
		invalidatable.InvalidateSession(cause)
	}
}

type invalidSessionError struct {
	cause error
}

func (e *invalidSessionError) Error() string {
	if e.cause == nil {
		return ErrSessionInvalid.Error()
	}
	return fmt.Sprintf("%s: %v", ErrSessionInvalid, e.cause)
}

func (e *invalidSessionError) Unwrap() []error {
	if e.cause == nil {
		return []error{ErrSessionInvalid}
	}
	return []error{ErrSessionInvalid, e.cause}
}

func sessionInvalidError(cause error) error {
	if cause == nil {
		return ErrSessionInvalid
	}
	return &invalidSessionError{cause: cause}
}

// useBudget is an optional client-side transactional use count. A limit of
// zero means that no local counting is enforced.
type useBudget struct {
	limit     int
	remaining int
}

func newUseBudget(limit int) useBudget {
	if limit <= 0 {
		return useBudget{}
	}
	return useBudget{limit: limit, remaining: limit}
}

func (b *useBudget) begin() error {
	if b.limit <= 0 {
		return nil
	}
	if b.remaining <= 0 {
		return ErrSessionUseExhausted
	}
	b.remaining--
	return nil
}

func (b useBudget) exhausted() bool {
	return b.limit > 0 && b.remaining == 0
}

// RemainingUses implements UsageMeter.
func (s *hmacSession) RemainingUses() (int, bool) {
	return s.uses.remaining, s.uses.limit > 0
}

// RemainingUses implements UsageMeter.
func (s *policySession) RemainingUses() (int, bool) {
	return s.uses.remaining, s.uses.limit > 0
}

type sessionStateSnapshot struct {
	handle      TPMHandle
	invalid     error
	uses        useBudget
	nonceCaller []byte
	nonceTPM    []byte
	auth        []byte
}

func snapshotSessionState(handle TPMHandle, invalid error, uses useBudget, nonceCaller, nonceTPM, auth []byte) sessionStateSnapshot {
	return sessionStateSnapshot{
		handle:      handle,
		invalid:     invalid,
		uses:        uses,
		nonceCaller: append([]byte(nil), nonceCaller...),
		nonceTPM:    append([]byte(nil), nonceTPM...),
		auth:        append([]byte(nil), auth...),
	}
}

func (s sessionStateSnapshot) restore(handle *TPMHandle, invalid *error, uses *useBudget, nonceCaller, nonceTPM *TPM2BNonce, auth *[]byte) {
	*handle = s.handle
	*invalid = s.invalid
	*uses = s.uses
	*nonceCaller = TPM2BNonce{Buffer: append([]byte(nil), s.nonceCaller...)}
	*nonceTPM = TPM2BNonce{Buffer: append([]byte(nil), s.nonceTPM...)}
	*auth = append([]byte(nil), s.auth...)
}

type hmacSessionTransaction struct {
	session *hmacSession
	saved   sessionStateSnapshot
	done    bool
}

// BeginCommand implements TransactionalSession.
func (s *hmacSession) BeginCommand() (SessionTransaction, error) {
	if s.invalid != nil {
		return nil, s.invalid
	}
	saved := snapshotSessionState(s.handle, s.invalid, s.uses, s.nonceCaller.Buffer, s.nonceTPM.Buffer, s.auth)
	if err := s.uses.begin(); err != nil {
		s.invalid = err
		return nil, err
	}
	return &hmacSessionTransaction{session: s, saved: saved}, nil
}

// Commit implements SessionTransaction.
func (tx *hmacSessionTransaction) Commit() {
	if tx.done {
		return
	}
	tx.done = true
	if tx.session.uses.exhausted() {
		tx.session.invalid = ErrSessionUseExhausted
	}
}

// Rollback implements SessionTransaction.
func (tx *hmacSessionTransaction) Rollback() {
	if tx.done {
		return
	}
	tx.done = true
	s := tx.session
	tx.saved.restore(&s.handle, &s.invalid, &s.uses, &s.nonceCaller, &s.nonceTPM, &s.auth)
}

type policySessionTransaction struct {
	session *policySession
	saved   sessionStateSnapshot
	done    bool
}

// BeginCommand implements TransactionalSession.
func (s *policySession) BeginCommand() (SessionTransaction, error) {
	if s.invalid != nil {
		return nil, s.invalid
	}
	saved := snapshotSessionState(s.handle, s.invalid, s.uses, s.nonceCaller.Buffer, s.nonceTPM.Buffer, s.auth)
	if err := s.uses.begin(); err != nil {
		s.invalid = err
		return nil, err
	}
	return &policySessionTransaction{session: s, saved: saved}, nil
}

// Commit implements SessionTransaction.
func (tx *policySessionTransaction) Commit() {
	if tx.done {
		return
	}
	tx.done = true
	if tx.session.uses.exhausted() {
		tx.session.invalid = ErrSessionUseExhausted
	}
}

// Rollback implements SessionTransaction.
func (tx *policySessionTransaction) Rollback() {
	if tx.done {
		return
	}
	tx.done = true
	s := tx.session
	tx.saved.restore(&s.handle, &s.invalid, &s.uses, &s.nonceCaller, &s.nonceTPM, &s.auth)
}
