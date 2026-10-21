// Package packetbuf supplies exclusively owned userspace packet storage.
package packetbuf

import (
	"errors"
	"sync"
)

// Headroom covers PPP(4), L2TP(10), UDP(8), ESP(8) and the largest CBC IV(16).
// Tailroom covers CBC padding(15), trailer(2) and HMAC-SHA1-96(12).
const (
	Headroom  = 64
	Tailroom  = 32
	MaxPacket = 65535
	// MaxWire fits a UDP/IPv4 payload, including NAT-T ESP overhead.
	MaxWire   = 65507
	smallSize = 2048
	largeSize = Headroom + MaxPacket + Tailroom
)

var ErrSize = errors.New("packet buffer: insufficient space or packet too large")
var small = sync.Pool{New: func() any { return &Buffer{storage: make([]byte, smallSize)} }}
var large = sync.Pool{New: func() any { return &Buffer{storage: make([]byte, largeSize)} }}

// Buffer must never be copied or used after Release. Ownership is exclusive;
// borrowed Bytes views expire on mutation, transfer, or Release. It is not safe
// for concurrent use. A successful queue submission transfers ownership.
type Buffer struct {
	storage    []byte
	start, end int
	released   bool
}

func Acquire(size int) (*Buffer, error) {
	if size < 0 || size > MaxPacket {
		return nil, ErrSize
	}
	p := &small
	if size > smallSize-Headroom-Tailroom {
		p = &large
	}
	b := p.Get().(*Buffer)
	b.released = false
	b.start = Headroom
	b.end = Headroom + size
	return b, nil
}
func Copy(data []byte) (*Buffer, error) {
	b, err := Acquire(len(data))
	if err == nil {
		copy(b.Bytes(), data)
	}
	return b, err
}
func (b *Buffer) Bytes() []byte { return b.storage[b.start:b.end:b.end] }
func (b *Buffer) Len() int      { return b.end - b.start }
func (b *Buffer) Prepend(n int) ([]byte, error) {
	if n < 0 || n > b.start {
		return nil, ErrSize
	}
	b.start -= n
	return b.storage[b.start : b.start+n : b.start+n], nil
}
func (b *Buffer) Append(n int) ([]byte, error) {
	if n < 0 || n > len(b.storage)-b.end {
		return nil, ErrSize
	}
	old := b.end
	b.end += n
	return b.storage[old:b.end:b.end], nil
}
func (b *Buffer) TrimFront(n int) error {
	if n < 0 || n > b.Len() {
		return ErrSize
	}
	b.start += n
	return nil
}
func (b *Buffer) Truncate(n int) error {
	if n < 0 || n > b.Len() {
		return ErrSize
	}
	b.end = b.start + n
	return nil
}
func (b *Buffer) Headroom() int { return b.start }
func (b *Buffer) Tailroom() int { return len(b.storage) - b.end }

// Release clears all storage, including consumed headers and failed decryptions.
// Exactly one owner must call it exactly once; no references may survive it.
func (b *Buffer) Release() {
	if b.released {
		panic("packet buffer: double release")
	}
	b.released = true
	clear(b.storage)
	b.start = 0
	b.end = 0
	if len(b.storage) == smallSize {
		small.Put(b)
	} else {
		large.Put(b)
	}
}
