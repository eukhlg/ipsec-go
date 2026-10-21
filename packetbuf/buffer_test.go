package packetbuf

import (
	"bytes"
	"testing"
)

func TestBoundsAndErasure(t *testing.T) {
	for _, size := range []int{0, 64, 1400, MaxPacket} {
		b, err := Acquire(size)
		if err != nil {
			t.Fatal(err)
		}
		if b.Headroom() != Headroom || b.Tailroom() < Tailroom || len(b.Bytes()) != size || cap(b.Bytes()) != size {
			t.Fatal("invalid reserved space")
		}
		original := b.Bytes()
		for i := range original {
			original[i] = 0xa5
		}
		h, _ := b.Prepend(Headroom)
		tail, _ := b.Append(Tailroom)
		for i := range h {
			h[i] = 7
		}
		for i := range tail {
			tail[i] = 9
		}
		if _, err = b.Prepend(1); err == nil {
			t.Fatal("headroom overflow")
		}
		if _, err = b.Append(largeSize); err == nil {
			t.Fatal("tailroom overflow")
		}
		if err = b.TrimFront(-1); err == nil {
			t.Fatal("negative trim")
		}
		if err = b.Truncate(b.Len() + 1); err == nil {
			t.Fatal("truncate overflow")
		}
		if err = b.TrimFront(Headroom); err != nil {
			t.Fatal(err)
		}
		if err = b.Truncate(size); err != nil {
			t.Fatal(err)
		}
		storage := b.storage
		b.Release()
		if !bytes.Equal(storage, make([]byte, len(storage))) {
			t.Fatal("pooled storage retained data")
		}
	}
	for _, n := range []int{-1, MaxPacket + 1, int(^uint(0) >> 1)} {
		if b, err := Acquire(n); err == nil {
			b.Release()
			t.Fatal("oversize accepted")
		}
	}
}
func TestIndependentOwnership(t *testing.T) {
	input := []byte("secret")
	a, _ := Copy(input)
	b, _ := Copy(input)
	a.Bytes()[0] = 'x'
	if !bytes.Equal(b.Bytes(), input) {
		t.Fatal("shared storage")
	}
	a.Release()
	if !bytes.Equal(b.Bytes(), input) {
		t.Fatal("release changed another packet")
	}
	b.Release()
}

func TestDoubleReleasePanics(t *testing.T) {
	b, _ := Acquire(1)
	b.Release()
	defer func() {
		if recover() == nil {
			t.Fatal("double release accepted")
		}
	}()
	b.Release()
}
