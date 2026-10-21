package packetbuf

import (
	"bytes"
	"errors"
	"fmt"
	"sync"
	"testing"
)

func fillPattern(p []byte) {
	for i := range p {
		p[i] = 0xa5
	}
}
func checkZero(t *testing.T, p []byte) {
	t.Helper()
	for i, v := range p {
		if v != 0 {
			t.Fatalf("storage[%d]=%x after erasure", i, v)
		}
	}
}
func releaseAndCheck(t *testing.T, b *Buffer, size int) {
	t.Helper()
	storage := b.storage
	b.Release()
	checkZero(t, storage)
	if b.dirtyStart != 0 || b.dirtyEnd != 0 {
		t.Fatal("dirty range not reset")
	}
	next, err := Acquire(size)
	if err != nil {
		t.Fatal(err)
	}
	checkZero(t, next.storage)
	next.Release()
}

func TestEveryWritableExposureIsErased(t *testing.T) {
	cases := []struct {
		name  string
		write func(*testing.T, *Buffer)
	}{
		{"bytes-in-place", func(t *testing.T, b *Buffer) {
			p := b.Bytes()
			fillPattern(p)
			if len(p) > 0 {
				p[len(p)/2] ^= 0xff
			}
		}},
		{"prepend-headroom", func(t *testing.T, b *Buffer) {
			p, err := b.Prepend(Headroom)
			if err != nil {
				t.Fatal(err)
			}
			fillPattern(p)
		}},
		{"append-tailroom", func(t *testing.T, b *Buffer) {
			p, err := b.Append(b.Tailroom())
			if err != nil {
				t.Fatal(err)
			}
			fillPattern(p)
		}},
		{"trim-then-prepend", func(t *testing.T, b *Buffer) {
			fillPattern(b.Bytes())
			n := b.Len() / 2
			if err := b.TrimFront(n); err != nil {
				t.Fatal(err)
			}
			p, err := b.Prepend(Headroom + n)
			if err != nil {
				t.Fatal(err)
			}
			fillPattern(p)
		}},
		{"truncate-retains-dirty-history", func(t *testing.T, b *Buffer) {
			fillPattern(b.Bytes())
			if err := b.Truncate(1); err != nil {
				t.Fatal(err)
			}
		}},
		{"grow-to-capacity", func(t *testing.T, b *Buffer) {
			if err := b.Truncate(0); err != nil {
				t.Fatal(err)
			}
			p, err := b.Append(b.Tailroom())
			if err != nil {
				t.Fatal(err)
			}
			fillPattern(p)
			if err := b.Truncate(0); err != nil {
				t.Fatal(err)
			}
		}},
	}
	for _, size := range []int{128, MaxPacket} {
		for _, tc := range cases {
			t.Run(fmt.Sprintf("%d/%s", size, tc.name), func(t *testing.T) {
				b, err := Acquire(size)
				if err != nil {
					t.Fatal(err)
				}
				checkZero(t, b.storage)
				tc.write(t, b)
				releaseAndCheck(t, b, size)
			})
		}
	}
	for _, size := range []int{128, 4000, MaxPacket} {
		t.Run(fmt.Sprintf("copy/%d", size), func(t *testing.T) {
			b, err := Copy(bytes.Repeat([]byte{0x55}, size))
			if err != nil {
				t.Fatal(err)
			}
			if b.dirtyEnd-b.dirtyStart != size {
				t.Fatal("copy exposure not tracked")
			}
			releaseAndCheck(t, b, size)
		})
	}
}

func TestReceiveUsesValidLengthWithoutForgettingPriorExposure(t *testing.T) {
	for _, size := range []int{128, MaxPacket} {
		for _, prior := range []bool{false, true} {
			t.Run(fmt.Sprintf("%d/prior=%t", size, prior), func(t *testing.T) {
				b, _ := Acquire(size)
				checkZero(t, b.storage)
				if prior {
					fillPattern(b.Bytes())
				}
				n := min(size, 1400)
				slots := []ReceiveSlot{{Buffer: b}}
				count, err := Receive(slots, func(slots []ReceiveSlot) (int, error) {
					if len(slots[0].Payload) != size || cap(slots[0].Payload) != size {
						t.Fatal("wrong read capacity")
					}
					fillPattern(slots[0].Payload[:n])
					slots[0].N = n
					return 1, nil
				})
				if err != nil || count != 1 || b.Len() != n || len(slots[0].Payload) != n || cap(slots[0].Payload) != n {
					t.Fatal("invalid receive result", count, err)
				}
				fillPattern(b.Bytes()) // in-place crypto uses only the valid receive view
				want := n
				if prior {
					want = size
				}
				if b.dirtyStart != Headroom || b.dirtyEnd != Headroom+want {
					t.Fatalf("dirty=[%d,%d), want length %d", b.dirtyStart, b.dirtyEnd, want)
				}
				header, _ := b.Prepend(Headroom)
				fillPattern(header)
				tail, _ := b.Append(Tailroom)
				fillPattern(tail)
				if err := b.TrimFront(Headroom + 4); err != nil {
					t.Fatal(err)
				}
				header, _ = b.Prepend(8)
				fillPattern(header)
				releaseAndCheck(t, b, size)
			})
		}
	}
}

func TestReceiveConservativeFailureErasure(t *testing.T) {
	for _, mode := range []string{"error", "panic", "negative-length", "oversize-length", "negative-count", "oversize-count"} {
		t.Run(mode, func(t *testing.T) {
			b, _ := Acquire(MaxPacket)
			slots := []ReceiveSlot{{Buffer: b}}
			func() {
				if mode == "panic" {
					defer func() {
						if recover() == nil {
							t.Error("panic swallowed")
						}
					}()
				}
				_, _ = Receive(slots, func(slots []ReceiveSlot) (int, error) {
					fillPattern(slots[0].Payload)
					slots[0].N = 1400
					switch mode {
					case "error":
						return 1, errors.New("read failure after progress")
					case "panic":
						panic("read panic")
					case "negative-length":
						slots[0].N = -1
					case "oversize-length":
						slots[0].N = MaxPacket + 1
					case "negative-count":
						return -1, nil
					case "oversize-count":
						return 2, nil
					}
					return 1, nil
				})
			}()
			if b.dirtyEnd != Headroom+MaxPacket {
				t.Fatalf("failure under-erased dirty end: %d", b.dirtyEnd)
			}
			if mode == "error" && len(slots[0].Payload) != 1400 {
				t.Fatal("valid partial progress lost")
			}
			releaseAndCheck(t, b, MaxPacket)
		})
	}
}

func TestReceiveBatchUntouchedSlotsAndZeroLength(t *testing.T) {
	a, _ := Acquire(MaxPacket)
	b, _ := Acquire(MaxPacket)
	slots := []ReceiveSlot{{Buffer: a}, {Buffer: b}}
	count, err := Receive(slots, func(slots []ReceiveSlot) (int, error) { slots[0].N = 0; return 1, nil })
	if count != 1 || err != nil || a.Len() != 0 || a.dirtyEnd != 0 || b.dirtyEnd != 0 {
		t.Fatal("untouched buffers dirtied", count, err)
	}
	releaseAndCheck(t, a, MaxPacket)
	releaseAndCheck(t, b, MaxPacket)
}

func TestConcurrentAcquireReleaseErasure(t *testing.T) {
	var wg sync.WaitGroup
	for worker := 0; worker < 8; worker++ {
		wg.Add(1)
		go func(worker int) {
			defer wg.Done()
			for i := 0; i < 2000; i++ {
				size := 1400
				if (worker+i)%2 == 0 {
					size = MaxPacket
				}
				b, err := Acquire(size)
				if err != nil {
					t.Error(err)
					return
				}
				// Inspect only while exclusively owned; never retain a released view.
				for _, v := range b.storage {
					if v != 0 {
						t.Error("previous owner's bytes survived")
						b.Release()
						return
					}
				}
				if size == MaxPacket {
					slots := []ReceiveSlot{{Buffer: b}}
					_, _ = Receive(slots, func(slots []ReceiveSlot) (int, error) {
						fillPattern(slots[0].Payload[:1400])
						slots[0].N = 1400
						return 1, nil
					})
				} else {
					fillPattern(b.Bytes())
				}
				p, _ := b.Prepend(Headroom)
				fillPattern(p)
				p, _ = b.Append(Tailroom)
				fillPattern(p)
				if err := b.TrimFront(Headroom); err != nil {
					t.Error(err)
				}
				if err := b.Truncate(1); err != nil {
					t.Error(err)
				}
				b.Release()
			}
		}(worker)
	}
	wg.Wait()
}

func BenchmarkAcquireWriteRelease1400(b *testing.B) {
	payload := bytes.Repeat([]byte{0x55}, 1400)
	for _, size := range []int{1400, MaxPacket} {
		b.Run(fmt.Sprint(size), func(b *testing.B) {
			b.ReportAllocs()
			b.SetBytes(1400)
			for i := 0; i < b.N; i++ {
				buffer, err := Acquire(size)
				if err != nil {
					b.Fatal(err)
				}
				if err := buffer.Truncate(1400); err != nil {
					b.Fatal(err)
				}
				copy(buffer.Bytes(), payload)
				buffer.Release()
			}
		})
	}
}
