package tpm2test

import (
	"errors"
	"testing"

	. "github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport/testhelper"
)

func useSession(t *testing.T, thetpm interface {
	Send([]byte) ([]byte, error)
}, sess Session) error {
	rsp, err := CreatePrimary{
		PrimaryHandle: AuthHandle{Handle: TPMRHOwner, Auth: sess},
		InPublic:      New2B(ECCSRKTemplate),
	}.Execute(thetpm)
	if err != nil {
		return err
	}
	_, err = (FlushContext{FlushHandle: rsp.ObjectHandle}).Execute(thetpm)
	return err
}

func TestClosedSessionHandleIsStale(t *testing.T) {
	thetpm := testhelper.Open(t)
	defer thetpm.Close()

	sess, closer, err := HMACSession(thetpm, TPMAlgSHA256, 16)
	if err != nil {
		t.Fatalf("HMACSession: %v", err)
	}
	if err := useSession(t, thetpm, sess); err != nil {
		t.Fatalf("command before close: %v", err)
	}
	if err := closer(); err != nil {
		t.Fatalf("closing session: %v", err)
	}
	if handle := sess.Handle(); handle != TPMRHNull {
		t.Errorf("Handle() after close = %#x, want TPM_RH_NULL", handle)
	}
	if err := useSession(t, thetpm, sess); !errors.Is(err, ErrSessionClosed) {
		t.Errorf("command after close = %v, want ErrSessionClosed", err)
	}
}

func TestExternallyFlushedSessionHandleIsStale(t *testing.T) {
	thetpm := testhelper.Open(t)
	defer thetpm.Close()

	sess, _, err := HMACSession(thetpm, TPMAlgSHA256, 16)
	if err != nil {
		t.Fatalf("HMACSession: %v", err)
	}
	handle := sess.Handle()
	if _, err := (FlushContext{FlushHandle: handle}).Execute(thetpm); err != nil {
		t.Fatalf("FlushContext: %v", err)
	}
	if err := useSession(t, thetpm, sess); !errors.Is(err, ErrStaleHandle) {
		t.Errorf("command after external flush = %v, want ErrStaleHandle", err)
	}
}

func TestClosedPolicySessionHandleIsStale(t *testing.T) {
	thetpm := testhelper.Open(t)
	defer thetpm.Close()

	sess, closer, err := PolicySession(thetpm, TPMAlgSHA256, 16)
	if err != nil {
		t.Fatalf("PolicySession: %v", err)
	}
	handle := sess.Handle()
	if _, err := (FlushContext{FlushHandle: handle}).Execute(thetpm); err != nil {
		t.Fatalf("FlushContext: %v", err)
	}
	if err := sess.Init(thetpm); !errors.Is(err, ErrStaleHandle) {
		t.Errorf("Init after external flush = %v, want ErrStaleHandle", err)
	}
	if err := closer(); err != nil {
		t.Errorf("closer after external flush: %v", err)
	}
}

func TestConnectionCloseInvalidatesSessionHandle(t *testing.T) {
	thetpm := testhelper.Open(t)

	sess, _, err := HMACSession(thetpm, TPMAlgSHA256, 16)
	if err != nil {
		thetpm.Close()
		t.Fatalf("HMACSession: %v", err)
	}
	if err := thetpm.Close(); err != nil {
		t.Fatalf("closing TPM connection: %v", err)
	}
	if err := useSession(t, thetpm, sess); !errors.Is(err, ErrStaleHandle) {
		t.Errorf("command after connection close = %v, want ErrStaleHandle", err)
	}
}
