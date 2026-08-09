package isakmp

import (
	"bytes"
	"errors"
	"testing"
)

func TestDHExchangeGroupsAgree(t *testing.T) {
	for _, test := range []struct {
		group uint16
		size  int
	}{{DHGroup2, 128}, {DHGroup14, 256}} {
		t.Run(string(rune(test.group)), func(t *testing.T) {
			alice, err := NewDHExchange(test.group, bytes.NewReader(bytes.Repeat([]byte{0x11}, 512)))
			if err != nil {
				t.Fatal(err)
			}
			bob, err := NewDHExchange(test.group, bytes.NewReader(bytes.Repeat([]byte{0x22}, 512)))
			if err != nil {
				t.Fatal(err)
			}
			if len(alice.Public()) != test.size || len(bob.Public()) != test.size {
				t.Fatalf("public sizes %d/%d", len(alice.Public()), len(bob.Public()))
			}
			aliceSecret, err := alice.SharedSecret(bob.Public())
			if err != nil {
				t.Fatal(err)
			}
			bobSecret, err := bob.SharedSecret(alice.Public())
			if err != nil {
				t.Fatal(err)
			}
			if len(aliceSecret) != test.size || !bytes.Equal(aliceSecret, bobSecret) {
				t.Fatal("DH secrets differ")
			}
		})
	}
}

func TestDHRejectsInvalidPublicValues(t *testing.T) {
	exchange, err := NewDHExchange(DHGroup2, bytes.NewReader(bytes.Repeat([]byte{0x33}, 256)))
	if err != nil {
		t.Fatal(err)
	}
	for _, value := range [][]byte{{1}, make([]byte, 128)} {
		if _, err := exchange.SharedSecret(value); !errors.Is(err, ErrInvalidCryptoInput) {
			t.Fatalf("error=%v", err)
		}
	}
	if _, err := NewDHExchange(DHGroup5, nil); !errors.Is(err, ErrUnsupportedTransform) {
		t.Fatalf("error=%v", err)
	}
}
