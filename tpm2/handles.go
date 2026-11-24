package tpm2

import (
	"errors"
	"fmt"

	"github.com/google/go-tpm/tpm2/internal/handles"
	"github.com/google/go-tpm/tpm2/transport"
)

// ErrStaleHandle is returned when a cached TPM handle no longer refers to the
// resource that was present when the handle was observed. This happens when the
// handle was flushed, or when the connection that owned it was closed.
var ErrStaleHandle = handles.ErrStale

// ErrSessionClosed is returned when a reusable session is used after its
// closer was called.
var ErrSessionClosed = fmt.Errorf("%w: session was closed", ErrStaleHandle)

// sessionHandle ties a cached session handle to the generation in which it was
// observed. The handle value alone cannot distinguish a live session from a
// numeric value the TPM has since reused.
type sessionHandle struct {
	token  handles.Token
	closed bool
}

func staleHandleError(value uint32) error {
	return fmt.Errorf("%w: handle %#x", ErrStaleHandle, value)
}

func (h *sessionHandle) started() bool {
	return h.token.Value() != 0
}

func (h *sessionHandle) closedError() error {
	if h.closed {
		return ErrSessionClosed
	}
	return nil
}

func (h *sessionHandle) bind(value TPMHandle, owner transport.TPM) {
	h.token.Track(uint32(value), owner)
	h.closed = false
}

// current returns the handle only if its generation still matches the cached
// generation. A stale handle is an error, not a value to send to the TPM.
func (h *sessionHandle) current() (TPMHandle, error) {
	value := h.token.Value()
	if value == 0 {
		if h.closed {
			return TPMRHNull, ErrSessionClosed
		}
		return TPMRHNull, nil
	}
	if h.closed {
		return TPMRHNull, ErrSessionClosed
	}
	if !h.token.Valid() {
		return TPMRHNull, staleHandleError(value)
	}
	return TPMHandle(value), nil
}

// invalidate marks the handle stale without clearing the cached value, so
// subsequent uses report why the handle cannot be used.
func (h *sessionHandle) invalidate() {
	h.token.Invalidate()
}

// discard invalidates the handle and forgets it. It is used when the TPM has
// already flushed a one-off session and the wrapper is allowed to start again.
func (h *sessionHandle) discard() {
	h.invalidate()
	h.token.Clear()
	h.closed = false
}

// close flushes a reusable session's handle. The wrapper stays closed even
// though the numeric value is forgotten.
func (h *sessionHandle) close(t transport.TPM) error {
	value := h.token.Value()
	if value == 0 {
		h.closed = true
		return nil
	}
	if !h.token.Valid() {
		h.token.Clear()
		h.closed = true
		return nil
	}
	if _, err := (&FlushContext{FlushHandle: TPMHandle(value)}).Execute(t); err != nil {
		return err
	}
	// FlushContext invalidates the generation as part of a successful flush.
	h.token.Clear()
	h.closed = true
	return nil
}

// cleanup flushes a one-off session after a command failed. The wrapper may be
// initialized again afterwards.
func (h *sessionHandle) cleanup(t transport.TPM) error {
	value := h.token.Value()
	if value == 0 {
		return nil
	}
	if !h.token.Valid() {
		h.token.Clear()
		return nil
	}
	if _, err := (&FlushContext{FlushHandle: TPMHandle(value)}).Execute(t); err != nil {
		return err
	}
	h.token.Clear()
	h.closed = false
	return nil
}

// sessionInvalidator is implemented by sessions whose handle can be named by a
// TPM error response.
type sessionInvalidator interface {
	invalidateHandle()
}

func invalidateSession(s Session) {
	if i, ok := s.(sessionInvalidator); ok {
		i.invalidateHandle()
	}
}

// noteSessionError marks the session named by a TPM error as stale. This covers
// handles that were flushed by another client or by a TPM resource manager,
// where the local generation registry could not observe the flush.
func noteSessionError(err error, sess []Session) error {
	var rc TPMRC
	if !errors.As(err, &rc) {
		return err
	}

	stale := false
	if rc >= TPMRCReferenceS0 && rc <= TPMRCReferenceS6 {
		index := int(rc - TPMRCReferenceS0)
		if index < len(sess) {
			invalidateSession(sess[index])
			stale = true
		}
	}

	if stale {
		return fmt.Errorf("%w: %w", ErrStaleHandle, err)
	}
	return err
}
