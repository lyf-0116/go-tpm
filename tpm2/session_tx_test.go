package tpm2

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"testing"

	"github.com/google/go-tpm/tpm2/transport"
)

type scriptedTransport struct {
	requests  [][]byte
	responses [][]byte
	errs      []error
	sends     int
}

func (t *scriptedTransport) Send(request []byte) ([]byte, error) {
	t.requests = append(t.requests, append([]byte(nil), request...))
	index := t.sends
	t.sends++
	if index < len(t.errs) && t.errs[index] != nil {
		return nil, t.errs[index]
	}
	if index < len(t.responses) {
		return t.responses[index], nil
	}
	return nil, errors.New("unexpected transport send")
}

type fakeSessionTransaction struct {
	session        *transactionalFakeSession
	savedRemaining int
	done           bool
}

func (tx *fakeSessionTransaction) Commit() {
	if tx.done {
		return
	}
	tx.done = true
}

func (tx *fakeSessionTransaction) Rollback() {
	if tx.done {
		return
	}
	tx.done = true
	tx.session.remainingUses = tx.savedRemaining
}

type transactionalFakeSession struct {
	handle        TPMHandle
	remainingUses int

	initCalls       int
	nonceCalls      int
	authorizeCalls  int
	validateCalls   int
	cleanupCalls    int
	beginCalls      int
	invalidated     bool
	invalidateCause error

	initErr      error
	newNonceErr  error
	authorizeErr error
	validateErr  error
	cleanupErr   error
	beginErr     error
}

func (s *transactionalFakeSession) Init(transport.TPM) error {
	s.initCalls++
	return s.initErr
}

func (s *transactionalFakeSession) CleanupFailure(transport.TPM) error {
	s.cleanupCalls++
	return s.cleanupErr
}

func (s *transactionalFakeSession) NonceTPM() TPM2BNonce {
	return TPM2BNonce{Buffer: []byte("nonce-tpm")}
}

func (s *transactionalFakeSession) NewNonceCaller() error {
	s.nonceCalls++
	return s.newNonceErr
}

func (s *transactionalFakeSession) BeginCommand() (SessionTransaction, error) {
	s.beginCalls++
	if s.beginErr != nil {
		return nil, s.beginErr
	}
	if s.remainingUses == 0 {
		return nil, ErrSessionUseExhausted
	}
	saved := s.remainingUses
	s.remainingUses--
	tx := &fakeSessionTransaction{session: s, savedRemaining: saved}
	return tx, nil
}

func (s *transactionalFakeSession) Authorize(_ TPMCC, _, _ []byte, _ []TPM2BName, _ int) (*TPMSAuthCommand, error) {
	s.authorizeCalls++
	if s.authorizeErr != nil {
		return nil, s.authorizeErr
	}
	return &TPMSAuthCommand{
		Handle:        s.handle,
		Nonce:         TPM2BNonce{Buffer: []byte("nonce-caller")},
		Authorization: TPM2BData{Buffer: []byte("hmac")},
	}, nil
}

func (s *transactionalFakeSession) Validate(_ TPMRC, _ TPMCC, _ []byte, _ []TPM2BName, _ int, auth *TPMSAuthResponse) error {
	s.validateCalls++
	return s.validateErr
}

func (s *transactionalFakeSession) IsEncryption() bool   { return false }
func (s *transactionalFakeSession) IsDecryption() bool   { return false }
func (s *transactionalFakeSession) Encrypt([]byte) error { return nil }
func (s *transactionalFakeSession) Decrypt([]byte) error { return nil }
func (s *transactionalFakeSession) Handle() TPMHandle    { return s.handle }

func (s *transactionalFakeSession) InvalidateSession(cause error) {
	s.invalidated = true
	s.invalidateCause = cause
}

func successGetRandomResponse(t *testing.T) []byte {
	t.Helper()
	var response bytes.Buffer
	const totalLength = uint32(25)
	_ = binary.Write(&response, binary.BigEndian, TPMSTSessions)
	_ = binary.Write(&response, binary.BigEndian, totalLength)
	_ = binary.Write(&response, binary.BigEndian, TPMRCSuccess)
	_ = binary.Write(&response, binary.BigEndian, uint32(4)) // parameter area length
	_ = binary.Write(&response, binary.BigEndian, uint16(2)) // random bytes length
	response.Write([]byte{0x11, 0x22})
	_ = binary.Write(&response, binary.BigEndian, uint16(1)) // nonce length
	response.WriteByte(0xAA)
	response.WriteByte(0x00)                                 // session attributes
	_ = binary.Write(&response, binary.BigEndian, uint16(1)) // HMAC length
	response.WriteByte(0xBB)
	if response.Len() != int(totalLength) {
		t.Fatalf("test response length = %d, want %d", response.Len(), totalLength)
	}
	return response.Bytes()
}

func errorResponse(rc TPMRC) []byte {
	var response bytes.Buffer
	_ = binary.Write(&response, binary.BigEndian, TPMSTSessions)
	_ = binary.Write(&response, binary.BigEndian, uint32(10))
	_ = binary.Write(&response, binary.BigEndian, rc)
	return response.Bytes()
}

func TestExecuteCommitsSessionUseOnSuccess(t *testing.T) {
	session := &transactionalFakeSession{handle: 0x02000001, remainingUses: 3}
	tpm := &scriptedTransport{responses: [][]byte{successGetRandomResponse(t)}}

	response, err := (GetRandom{BytesRequested: 2}).Execute(tpm, session)
	if err != nil {
		t.Fatalf("Execute() error = %v", err)
	}
	if !bytes.Equal(response.RandomBytes.Buffer, []byte{0x11, 0x22}) {
		t.Fatalf("random bytes = %x", response.RandomBytes.Buffer)
	}
	if session.beginCalls != 1 || session.authorizeCalls != 1 || session.validateCalls != 1 {
		t.Fatalf("calls = begin %d authorize %d validate %d", session.beginCalls, session.authorizeCalls, session.validateCalls)
	}
	if session.remainingUses != 2 {
		t.Fatalf("remaining uses = %d, want 2", session.remainingUses)
	}
	if session.cleanupCalls != 0 || session.invalidated {
		t.Fatalf("success path cleaned up %d times or invalidated = %v", session.cleanupCalls, session.invalidated)
	}
}

func TestExecuteRollsBackSessionUseOnRejectedCommand(t *testing.T) {
	session := &transactionalFakeSession{handle: 0x02000001, remainingUses: 3}
	tpm := &scriptedTransport{responses: [][]byte{errorResponse(TPMRC(0x1E5))}}

	_, err := (GetRandom{BytesRequested: 2}).Execute(tpm, session)
	if err == nil {
		t.Fatal("Execute() succeeded, want TPM error")
	}
	var rc TPMRC
	if !errors.As(err, &rc) || rc != TPMRC(0x1E5) {
		t.Fatalf("Execute() error = %v, want TPMRC 0x1e5", err)
	}
	if session.remainingUses != 3 {
		t.Fatalf("remaining uses = %d, want rolled back to 3", session.remainingUses)
	}
	if session.cleanupCalls != 1 {
		t.Fatalf("cleanup calls = %d, want 1", session.cleanupCalls)
	}
	if session.invalidated {
		t.Fatal("rejected command should roll back, not invalidate the session")
	}
}

func TestExecuteRollsBackAndInvalidatesSessionOnTransportFailure(t *testing.T) {
	for _, transportErr := range []error{context.DeadlineExceeded, io.EOF} {
		t.Run(transportErr.Error(), func(t *testing.T) {
			session := &transactionalFakeSession{handle: 0x02000001, remainingUses: 3}
			tpm := &scriptedTransport{errs: []error{transportErr}}

			_, err := (GetRandom{BytesRequested: 2}).Execute(tpm, session)
			if !errors.Is(err, transportErr) {
				t.Fatalf("Execute() error = %v, want %v", err, transportErr)
			}
			if session.remainingUses != 3 {
				t.Fatalf("remaining uses = %d, want rolled back to 3", session.remainingUses)
			}
			if !session.invalidated || !errors.Is(session.invalidateCause, transportErr) {
				t.Fatalf("session invalidation = %v cause %v", session.invalidated, session.invalidateCause)
			}
			if session.cleanupCalls != 0 {
				t.Fatalf("cleanup calls = %d, want no remote cleanup on broken transport", session.cleanupCalls)
			}
		})
	}
}

func TestRejectedCommandsDoNotConsumeSessionUseBudget(t *testing.T) {
	session := &transactionalFakeSession{handle: 0x02000001, remainingUses: 2}
	tpm := &scriptedTransport{
		responses: [][]byte{
			errorResponse(TPMRC(0x1E5)),
			errorResponse(TPMRC(0x1E5)),
			successGetRandomResponse(t),
		},
	}
	command := GetRandom{BytesRequested: 2}

	for range 2 {
		if _, err := command.Execute(tpm, session); err == nil {
			t.Fatal("Execute() succeeded, want rejection")
		}
	}
	if session.remainingUses != 2 {
		t.Fatalf("remaining uses after failures = %d, want 2", session.remainingUses)
	}
	if _, err := command.Execute(tpm, session); err != nil {
		t.Fatalf("Execute() after rolled-back failures error = %v", err)
	}
	if session.remainingUses != 1 {
		t.Fatalf("remaining uses after success = %d, want 1", session.remainingUses)
	}
}

func TestExecuteRollsBackSessionUseOnMalformedResponse(t *testing.T) {
	session := &transactionalFakeSession{handle: 0x02000001, remainingUses: 3}
	tpm := &scriptedTransport{responses: [][]byte{errorResponse(TPMRCSuccess)}}

	_, err := (GetRandom{BytesRequested: 2}).Execute(tpm, session)
	if err == nil {
		t.Fatal("Execute() succeeded, want response parse error")
	}
	if session.remainingUses != 3 {
		t.Fatalf("remaining uses = %d, want rolled back to 3", session.remainingUses)
	}
	if session.cleanupCalls != 1 {
		t.Fatalf("cleanup calls = %d, want 1", session.cleanupCalls)
	}
}

func TestExecuteRollsBackSessionUseOnAssemblyFailure(t *testing.T) {
	session := &transactionalFakeSession{
		handle:        0x02000001,
		remainingUses: 3,
		newNonceErr:   errors.New("no entropy"),
	}
	tpm := &scriptedTransport{}

	_, err := (GetRandom{BytesRequested: 2}).Execute(tpm, session)
	if !errors.Is(err, session.newNonceErr) {
		t.Fatalf("Execute() error = %v, want %v", err, session.newNonceErr)
	}
	if session.remainingUses != 3 {
		t.Fatalf("remaining uses = %d, want rolled back to 3", session.remainingUses)
	}
	if session.cleanupCalls != 1 {
		t.Fatalf("cleanup calls = %d, want 1", session.cleanupCalls)
	}
	if tpm.sends != 0 {
		t.Fatalf("transport sends = %d, want 0", tpm.sends)
	}
}

func TestExecuteCleansUpWhenSessionInitializationFails(t *testing.T) {
	session := &transactionalFakeSession{
		handle:  0x02000001,
		initErr: errors.New("init failed"),
	}
	tpm := &scriptedTransport{}

	_, err := (GetRandom{BytesRequested: 2}).Execute(tpm, session)
	if !errors.Is(err, session.initErr) {
		t.Fatalf("Execute() error = %v, want %v", err, session.initErr)
	}
	if session.beginCalls != 0 {
		t.Fatalf("begin calls = %d, want 0 after Init failure", session.beginCalls)
	}
	if session.cleanupCalls != 1 {
		t.Fatalf("cleanup calls = %d, want 1", session.cleanupCalls)
	}
}

func TestHMACSessionTransactionRestoresMutableState(t *testing.T) {
	session := &hmacSession{
		handle:         0x02000042,
		sessionOptions: sessionOptions{auth: []byte("old-auth")},
		nonceCaller:    TPM2BNonce{Buffer: []byte("caller")},
		nonceTPM:       TPM2BNonce{Buffer: []byte("tpm")},
		uses:           newUseBudget(2),
	}

	tx, err := session.BeginCommand()
	if err != nil {
		t.Fatalf("BeginCommand() error = %v", err)
	}
	if session.uses.remaining != 1 {
		t.Fatalf("remaining after begin = %d, want 1", session.uses.remaining)
	}

	session.handle = TPMRHNull
	session.auth = []byte("new-auth")
	session.nonceCaller.Buffer[0] ^= 0xFF
	session.nonceTPM = TPM2BNonce{Buffer: []byte("new-tpm-nonce")}
	session.uses.remaining = 0

	tx.Rollback()
	if session.handle != TPMHandle(0x02000042) {
		t.Fatalf("handle = %#x", session.handle)
	}
	if string(session.auth) != "old-auth" {
		t.Fatalf("auth = %q", session.auth)
	}
	if string(session.nonceCaller.Buffer) != "caller" {
		t.Fatalf("nonceCaller = %q", session.nonceCaller.Buffer)
	}
	if string(session.nonceTPM.Buffer) != "tpm" {
		t.Fatalf("nonceTPM = %q", session.nonceTPM.Buffer)
	}
	if session.uses.remaining != 2 {
		t.Fatalf("remaining after rollback = %d, want 2", session.uses.remaining)
	}
}

func TestHMACSessionUseExhaustionAndTransportInvalidation(t *testing.T) {
	session := HMAC(TPMAlgSHA256, 16, MaxUses(1)).(*hmacSession)

	tx, err := session.BeginCommand()
	if err != nil {
		t.Fatalf("BeginCommand() error = %v", err)
	}
	tx.Commit()
	if !errors.Is(session.invalid, ErrSessionUseExhausted) {
		t.Fatalf("invalid = %v, want %v", session.invalid, ErrSessionUseExhausted)
	}
	if _, err := session.BeginCommand(); !errors.Is(err, ErrSessionUseExhausted) {
		t.Fatalf("second BeginCommand() error = %v, want exhausted", err)
	}

	transportErr := errors.New("connection reset")
	session.InvalidateSession(transportErr)
	if session.Handle() != TPMRHNull {
		t.Fatalf("Handle() = %#x, want null", session.Handle())
	}
	if err := session.Init(nil); !errors.Is(err, ErrSessionInvalid) || !errors.Is(err, transportErr) {
		t.Fatalf("Init() error = %v, want invalid wrapping %v", err, transportErr)
	}
}
