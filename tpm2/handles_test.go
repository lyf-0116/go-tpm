package tpm2

import (
	"errors"
	"testing"
)

func TestTPMSessionReferenceErrorMarksHandleStale(t *testing.T) {
	sess := &hmacSession{}
	sess.handle.bind(TPMHandle(0x02000001), nil)

	err := noteSessionError(TPMRCReferenceS0, []Session{sess})
	if !errors.Is(err, ErrStaleHandle) {
		t.Errorf("noteSessionError() = %v, want ErrStaleHandle", err)
	}
	if !errors.Is(err, TPMRCReferenceS0) {
		t.Errorf("noteSessionError() = %v, want it to preserve TPM_RC_REFERENCE_S0", err)
	}
	if _, err := sess.handle.current(); !errors.Is(err, ErrStaleHandle) {
		t.Errorf("handle after TPM session error = %v, want ErrStaleHandle", err)
	}
}

func TestNonReferenceSessionErrorDoesNotMarkHandleStale(t *testing.T) {
	sess := &hmacSession{}
	sess.handle.bind(TPMHandle(0x02000001), nil)

	if err := noteSessionError(TPMRCAttributes, []Session{sess}); !errors.Is(err, TPMRCAttributes) {
		t.Fatalf("noteSessionError() = %v, want TPM_RC_ATTRIBUTES preserved", err)
	}
	if _, err := sess.handle.current(); err != nil {
		t.Errorf("handle after non-reference error = %v, want it to stay valid", err)
	}
}
