package esp

import (
	"bytes"
	"math/rand/v2"
	"sync"
	"testing"

	"github.com/eukhlg/netio/packetbuf"
)

// Reserved packets sealed concurrently and out of order must be identical to
// serial SealBuffer output and open in sequence order at the peer.
// patternReader is an endless deterministic IV source.
type patternReader struct{ n byte }

func (r *patternReader) Read(p []byte) (int, error) {
	for i := range p {
		r.n++
		p[i] = r.n
	}
	return len(p), nil
}

func TestReserveSealParallelMatchesSerial(t *testing.T) {
	config := testConfig(7)
	config.Random = &patternReader{}
	parallel, err := NewSA(config)
	if err != nil {
		t.Fatal(err)
	}
	config = testConfig(7)
	config.Random = &patternReader{}
	serial, err := NewSA(config)
	if err != nil {
		t.Fatal(err)
	}
	inbound, err := NewSA(testConfig(7))
	if err != nil {
		t.Fatal(err)
	}
	const count = 200
	buffers := make([]*packetbuf.Buffer, count)
	packets := make([]SealPacket, count)
	payloads := make([][]byte, count)
	for i := range buffers {
		payloads[i] = bytes.Repeat([]byte{byte(i)}, 1+i%97)
		b, err := packetbuf.Copy(payloads[i])
		if err != nil {
			t.Fatal(err)
		}
		buffers[i] = b
		if packets[i], err = parallel.ReserveSeal(b, 17); err != nil {
			t.Fatal(err)
		}
	}
	order := rand.Perm(count)
	var wg sync.WaitGroup
	for w := 0; w < 4; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for k := w; k < count; k += 4 {
				packets[order[k]].Seal()
			}
		}()
	}
	wg.Wait()
	for i, b := range buffers {
		reference, err := packetbuf.Copy(payloads[i])
		if err != nil {
			t.Fatal(err)
		}
		if err := serial.SealBuffer(reference, 17); err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(b.Bytes(), reference.Bytes()) {
			t.Fatalf("packet %d differs from serial sealing", i)
		}
		reference.Release()
		got, next, err := inbound.Open(b.Bytes())
		if err != nil || next != 17 || !bytes.Equal(got, payloads[i]) {
			t.Fatalf("packet %d: next=%d err=%v", i, next, err)
		}
		b.Release()
	}
}
