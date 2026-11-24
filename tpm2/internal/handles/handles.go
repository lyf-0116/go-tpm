// Package handles tracks the client-side lifetime of TPM handles.
//
// A TPM handle value can be reused after the resource it names has been
// flushed. A cached handle value alone therefore says nothing about whether the
// resource it used to name is still loaded. Tokens tie a cached value to the
// generation in which it was observed. Flushing a handle, or closing the
// connection whose resource manager owns it, advances that generation and
// makes every older token stale.
package handles

import (
	"errors"
	"reflect"
	"sync"
	"sync/atomic"
)

// ErrStale is returned when a cached handle no longer refers to the resource
// that was present when the handle was recorded.
var ErrStale = errors.New("tpm2: stale TPM handle")

// State is the lifetime state of one numeric TPM handle value.
type State struct {
	generation atomic.Uint64
}

var registry = struct {
	sync.Mutex
	states map[key]*State
}{
	states: make(map[key]*State),
}

type key struct {
	owner any
	value uint32
}

// Token is a cached handle value and the generation in which it was observed.
// The zero value is not tracking a handle.
type Token struct {
	value      uint32
	owner      any
	state      *State
	generation uint64
}

// Track records the current generation of value.
func (t *Token) Track(value uint32, owner any) {
	t.value = value
	t.owner = ownerKey(owner)
	t.state = stateFor(t.owner, value)
	t.generation = t.state.generation.Load()
}

// Clear stops tracking the handle. It does not invalidate the handle itself.
func (t *Token) Clear() {
	*t = Token{}
}

// Value returns the cached numeric handle value.
func (t Token) Value() uint32 {
	return t.value
}

// Valid reports whether the cached handle still belongs to the generation in
// which it was recorded.
func (t Token) Valid() bool {
	if t.value == 0 || t.state == nil {
		return false
	}
	return t.generation == t.state.generation.Load()
}

// Invalidate advances the generation of value and stops handing out its old
// state to newly tracked tokens.
func (t *Token) Invalidate() {
	if t.value == 0 {
		return
	}
	invalidate(t.owner, t.value)
}

// Invalidate advances the generation of an owned handle.
func Invalidate(value uint32, owner any) {
	invalidate(ownerKey(owner), value)
}

func invalidate(owner any, value uint32) {
	if value == 0 {
		return
	}
	registry.Lock()
	defer registry.Unlock()
	if state, ok := registry.states[key{owner, value}]; ok {
		state.generation.Add(1)
		delete(registry.states, key{owner, value})
	}
}

// InvalidateAll invalidates the handles owned by a closing connection.
func InvalidateAll(owner any) {
	owner = ownerKey(owner)
	registry.Lock()
	defer registry.Unlock()
	for handle, state := range registry.states {
		if handle.owner != owner {
			continue
		}
		state.generation.Add(1)
		delete(registry.states, handle)
	}
}

func stateFor(owner any, value uint32) *State {
	registry.Lock()
	defer registry.Unlock()
	if state, ok := registry.states[key{owner, value}]; ok {
		return state
	}
	state := new(State)
	registry.states[key{owner, value}] = state
	return state
}

// ownerKey turns common transport pointer values into a comparable identity.
// Non-pointer transports share the nil owner and are invalidated together.
func ownerKey(owner any) any {
	if owner == nil {
		return nil
	}
	value := reflect.ValueOf(owner)
	switch value.Kind() {
	case reflect.Ptr, reflect.Chan, reflect.Map, reflect.Func, reflect.UnsafePointer:
		return value.Pointer()
	default:
		return nil
	}
}
