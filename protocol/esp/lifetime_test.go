package esp

import (
	"bytes"
	"errors"
	"testing"
	"time"
)

func TestLifetimeErrorReasons(t *testing.T) {
	now := time.Unix(1, 0)
	cases := []struct {
		name   string
		config func(*SAConfig)
		before func()
		reason LifetimeReason
		limit  uint64
	}{
		{name: "packets", config: func(c *SAConfig) { c.Limits = Limits{Packets: 2} }, reason: LifetimePackets, limit: 2},
		{name: "bytes", config: func(c *SAConfig) { c.Limits = Limits{Bytes: 25} }, reason: LifetimeBytes, limit: 25},
		{name: "time", config: func(c *SAConfig) { c.Lifetime = time.Minute }, before: func() { now = now.Add(time.Minute) }, reason: LifetimeTime},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			now = time.Unix(1, 0)
			config := testConfig(0x2a)
			config.Now = func() time.Time { return now }
			tc.config(&config)
			sa, err := NewSA(config)
			if err != nil {
				t.Fatal(err)
			}
			for i := 0; i < 2; i++ {
				if _, err := sa.Seal(bytes.Repeat([]byte{1}, 10), 17); err != nil {
					t.Fatalf("seal %d: %v", i, err)
				}
			}
			if tc.before != nil {
				tc.before()
			}
			_, err = sa.Seal(bytes.Repeat([]byte{1}, 10), 17)
			if !errors.Is(err, ErrSALifetime) {
				t.Fatalf("error=%v, want ErrSALifetime", err)
			}
			var lifetime *LifetimeError
			if !errors.As(err, &lifetime) {
				t.Fatalf("error %T is not *LifetimeError", err)
			}
			if lifetime.Reason != tc.reason || lifetime.Limit != tc.limit || lifetime.SPI != 0x2a {
				t.Fatalf("lifetime=%+v", lifetime)
			}
			if lifetime.Packets != 2 || lifetime.Bytes != 20 {
				t.Fatalf("counters=%d/%d, want 2/20", lifetime.Packets, lifetime.Bytes)
			}
			if tc.reason == LifetimeTime && (lifetime.Age != time.Minute || lifetime.Lifetime != time.Minute) {
				t.Fatalf("age=%s lifetime=%s", lifetime.Age, lifetime.Lifetime)
			}
			if lifetime.Reason.String() != tc.name {
				t.Fatalf("reason string=%q", lifetime.Reason)
			}
		})
	}
}

func TestLifetimeErrorOnOpen(t *testing.T) {
	config := testConfig(0x2b)
	outbound, _ := NewSA(config)
	config.Limits = Limits{Bytes: 15}
	inbound, _ := NewSA(config)
	for i := 0; i < 2; i++ {
		wire, err := outbound.Seal(bytes.Repeat([]byte{2}, 10), 17)
		if err != nil {
			t.Fatal(err)
		}
		_, _, err = inbound.Open(wire)
		if i == 0 && err != nil {
			t.Fatalf("first open: %v", err)
		}
		if i == 1 {
			var lifetime *LifetimeError
			if !errors.As(err, &lifetime) || lifetime.Reason != LifetimeBytes || lifetime.Bytes != 10 || lifetime.Limit != 15 {
				t.Fatalf("second open err=%v", err)
			}
		}
	}
}
