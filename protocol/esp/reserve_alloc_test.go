//go:build !race

package esp

import (
	"bytes"
	"testing"

	"github.com/eukhlg/netio/packetbuf"
)

// The race detector drops sync.Pool entries at random, so this runs without it.
func TestReserveSealDoesNotAllocate(t *testing.T) {
	config := testConfig(9)
	config.Random = &patternReader{}
	sa, err := NewSA(config)
	if err != nil {
		t.Fatal(err)
	}
	payload := bytes.Repeat([]byte{1}, 1400)
	seal := func() {
		b, err := packetbuf.Copy(payload)
		if err != nil {
			t.Fatal(err)
		}
		p, err := sa.ReserveSeal(b, 17)
		if err != nil {
			t.Fatal(err)
		}
		p.Seal()
		b.Release()
	}
	seal() // warm the buffer and crypto pools
	allocs := testing.AllocsPerRun(200, seal)
	if allocs != 0 {
		t.Fatalf("reserve+seal allocated %.1f times", allocs)
	}
}
