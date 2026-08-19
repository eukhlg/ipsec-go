package isakmp

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"
)

func TestControlPlaneCreatesReplaysAndExpiresSA(t *testing.T) {
	control, err := NewControlPlane(ControlPlaneConfig{PreSharedKey: []byte("psk"), ResponderID: Identification{IDType: IDIPv4Address, Data: []byte{192, 0, 2, 1}}, Random: bytes.NewReader(bytes.Repeat([]byte{0x77}, 1024)), MaxPhase1SAs: 1, Phase1Lifetime: time.Minute, HandshakeTimeout: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	sa := SecurityAssociation{DOI: DOIIPsec, Situation: SituationIdentityOnly, Proposals: []Proposal{{Number: 1, ProtocolID: ProtocolIKE, Transforms: []Transform{phase1Transform(EncryptionAESCBC, HashSHA1, DHGroup2, 128)}}}}
	request, _ := (Packet{InitiatorCookie: Cookie{1}, Exchange: ExchangeIdentityProtect, Payloads: []Payload{sa}}).MarshalBinary()
	peer := &net.UDPAddr{IP: net.IPv4(192, 0, 2, 10), Port: 500}
	now := time.Unix(1, 0)
	first, err := control.HandleDatagram(peer, request, now)
	if err != nil || len(first.Reply) == 0 {
		t.Fatalf("reply=%x err=%v", first.Reply, err)
	}
	replay, err := control.HandleDatagram(peer, request, now.Add(time.Second))
	if err != nil || !bytes.Equal(replay.Reply, first.Reply) {
		t.Fatalf("replay=%x err=%v", replay.Reply, err)
	}
	secondRequest, _ := (Packet{InitiatorCookie: Cookie{2}, Exchange: ExchangeIdentityProtect, Payloads: []Payload{sa}}).MarshalBinary()
	if _, err := control.HandleDatagram(peer, secondRequest, now.Add(2*time.Second)); !errors.Is(err, ErrSALimit) {
		t.Fatalf("error=%v", err)
	}
	if _, err := control.HandleDatagram(peer, secondRequest, now.Add(2*time.Minute)); err != nil {
		t.Fatal(err)
	}
	if control.SACount() != 1 {
		t.Fatalf("SAs=%d", control.SACount())
	}
	events := control.Maintain(now.Add(2 * time.Minute))
	if len(events) != 1 || events[0].Type != LifecycleExpireIKE {
		t.Fatalf("expiry events=%#v", events)
	}
}

func TestControlPlaneHonorsNegotiatedPhase1Lifetime(t *testing.T) {
	control, err := NewControlPlane(ControlPlaneConfig{PreSharedKey: []byte("psk"), ResponderID: Identification{IDType: IDIPv4Address, Data: []byte{192, 0, 2, 1}}, Random: bytes.NewReader(bytes.Repeat([]byte{0x66}, 1024)), MaxPhase1SAs: 1, Phase1Lifetime: time.Hour, HandshakeTimeout: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	transform := phase1Transform(EncryptionAESCBC, HashSHA1, DHGroup2, 128)
	transform.Attributes = append(transform.Attributes, TVAttribute(AttributeP1LifeType, LifeTypeSeconds), TVAttribute(AttributeP1LifeValue, 1))
	sa := SecurityAssociation{DOI: DOIIPsec, Situation: SituationIdentityOnly, Proposals: []Proposal{{Number: 1, ProtocolID: ProtocolIKE, Transforms: []Transform{transform}}}}
	request, _ := (Packet{InitiatorCookie: Cookie{1}, Exchange: ExchangeIdentityProtect, Payloads: []Payload{sa}}).MarshalBinary()
	peer := &net.UDPAddr{IP: net.IPv4(192, 0, 2, 10), Port: 500}
	now := time.Unix(1, 0)
	if _, err := control.HandleDatagram(peer, request, now); err != nil {
		t.Fatal(err)
	}
	request2, _ := (Packet{InitiatorCookie: Cookie{2}, Exchange: ExchangeIdentityProtect, Payloads: []Payload{sa}}).MarshalBinary()
	if _, err := control.HandleDatagram(peer, request2, now.Add(2*time.Second)); err != nil {
		t.Fatal(err)
	}
}

func TestEstablishedPhase1LifetimeIsSoft(t *testing.T) {
	cookie := Cookie{1}
	now := time.Unix(100, 0)
	sa := &controlSA{
		main:      &MainModeResponder{state: MainModeEstablished},
		quick:     make(map[uint32]*QuickModeResponder),
		expires:   now.Add(-time.Second),
		updated:   now.Add(-time.Hour),
		peerAddr:  &net.UDPAddr{IP: net.IPv4(192, 0, 2, 10), Port: 500},
		responses: make(map[string][]byte),
	}
	control := &ControlPlane{config: ControlPlaneConfig{HandshakeTimeout: time.Minute}, sas: map[Cookie]*controlSA{cookie: sa}}

	events := control.Maintain(now)
	if len(events) != 0 || control.SACount() != 1 || !sa.softExpired {
		t.Fatalf("events=%#v SAs=%d softExpired=%v", events, control.SACount(), sa.softExpired)
	}
}

func TestPhase1ReplacementTransfersChildWithoutImmediateRekey(t *testing.T) {
	now := time.Unix(100, 0)
	oldCookie := Cookie{1}
	newCookie := Cookie{2}
	peerIP := netip.MustParseAddr("198.51.100.20")
	identity := Identification{IDType: IDIPv4Address, Data: []byte{10, 0, 0, 20}}
	pair := ESPPair{
		Transform:       ESPTransform{Encryption: TransformESPAES, Authentication: ESPAuthHMACSHA196, Encapsulation: EncapsulationTransport, KeyBits: 128, LifetimeSeconds: 3600},
		ResponderCookie: oldCookie,
		Inbound:         ESPDirectionalKeys{SPI: 1, EncryptionKey: []byte{1}, AuthenticationKey: []byte{2}},
		Outbound:        ESPDirectionalKeys{SPI: 2, EncryptionKey: []byte{3}, AuthenticationKey: []byte{4}},
	}
	oldSA := &controlSA{
		peerIP:      peerIP,
		main:        &MainModeResponder{state: MainModeEstablished, peerIdentity: identity},
		quick:       make(map[uint32]*QuickModeResponder),
		activePair:  clonePair(pair),
		nextRekey:   now.Add(30 * time.Minute),
		established: now.Add(-time.Hour),
	}
	newSA := &controlSA{
		peerIP:         peerIP,
		peerAddr:       &net.UDPAddr{IP: net.IPv4(198, 51, 100, 20), Port: 500},
		main:           &MainModeResponder{state: MainModeEstablished, peerIdentity: identity, initiatorCookie: Cookie{3}, responderCookie: newCookie},
		quick:          make(map[uint32]*QuickModeResponder),
		quickInitiated: make(map[uint32]*QuickModeInitiator),
		established:    now,
	}
	control := &ControlPlane{sas: map[Cookie]*controlSA{oldCookie: oldSA, newCookie: newSA}}

	events := control.adoptPhase1Replacement(newCookie, newSA)
	if oldSA.successor != newCookie || len(newSA.predecessors) != 1 || newSA.predecessors[0] != oldCookie {
		t.Fatalf("successor=%x predecessors=%x", oldSA.successor, newSA.predecessors)
	}
	if len(events) != 1 || events[0].Type != LifecycleRebindIKE || events[0].ResponderCookie != oldCookie || events[0].ReplacementCookie != newCookie {
		t.Fatalf("events=%#v", events)
	}
	if !newSA.nextRekey.Equal(oldSA.nextRekey) || newSA.activePair.Transform.Encryption == 0 || newSA.activePair.ResponderCookie != newCookie || newSA.activePair.InitiatorCookie != (Cookie{3}) {
		t.Fatalf("nextRekey=%v activePair=%#v", newSA.nextRekey, newSA.activePair)
	}
	if datagrams := control.PollRekey(now); len(datagrams) != 0 {
		t.Fatalf("immediate rekey datagrams=%d", len(datagrams))
	}
	if events := control.closeControlSA(oldCookie); len(events) != 0 {
		t.Fatalf("predecessor close events=%#v", events)
	}
	if control.sas[oldCookie] != nil || control.sas[newCookie] != newSA || len(newSA.predecessors) != 0 {
		t.Fatalf("SAs=%#v predecessors=%x", control.sas, newSA.predecessors)
	}
}

func TestFailedPhase1ReplacementRestoresPredecessor(t *testing.T) {
	oldCookie := Cookie{1}
	newCookie := Cookie{2}
	oldSA := &controlSA{main: &MainModeResponder{state: MainModeEstablished}, quick: make(map[uint32]*QuickModeResponder), successor: newCookie}
	newSA := &controlSA{main: &MainModeResponder{state: MainModeFailed}, quick: make(map[uint32]*QuickModeResponder), predecessors: []Cookie{oldCookie}, activePair: ESPPair{Transform: ESPTransform{Encryption: TransformESPAES}}}
	control := &ControlPlane{sas: map[Cookie]*controlSA{oldCookie: oldSA, newCookie: newSA}}

	events := control.closeControlSA(newCookie)
	if len(events) != 1 || events[0].Type != LifecycleRebindIKE || events[0].ResponderCookie != newCookie || events[0].ReplacementCookie != oldCookie {
		t.Fatalf("events=%#v", events)
	}
	if oldSA.successor != (Cookie{}) || control.sas[oldCookie] != oldSA || control.sas[newCookie] != nil {
		t.Fatalf("successor=%x SAs=%#v", oldSA.successor, control.sas)
	}
}

func TestControlSAResponseCacheIsBounded(t *testing.T) {
	sa := &controlSA{responses: make(map[string][]byte)}
	for i := byte(0); i < 10; i++ {
		sa.cacheResponse([]byte{i}, []byte{i + 1})
	}
	if len(sa.responses) != 8 || len(sa.responseOrder) != 8 {
		t.Fatalf("responses=%d order=%d", len(sa.responses), len(sa.responseOrder))
	}
	if _, ok := sa.responses[string([]byte{0})]; ok {
		t.Fatal("old response was not evicted")
	}
	if got := sa.responses[string([]byte{9})]; !bytes.Equal(got, []byte{10}) {
		t.Fatalf("reply=%x", got)
	}
}

func TestControlPlaneAllowsAuthenticatedNATTPortMigration(t *testing.T) {
	cookie := Cookie{9}
	main := &MainModeResponder{state: MainModeEstablished, capabilities: PeerCapabilities{NATTRFC3947: true}, nat: NATDetection{RemoteNAT: true}, natDetectionComplete: true}
	sa := &controlSA{peer: addressKey(&net.UDPAddr{IP: net.IPv4(198, 51, 100, 20), Port: 500}), peerIP: netip.MustParseAddr("198.51.100.20"), main: main, quick: make(map[uint32]*QuickModeResponder), quickUpdated: make(map[uint32]time.Time), responses: make(map[string][]byte), expires: time.Now().Add(time.Hour)}
	control := &ControlPlane{config: ControlPlaneConfig{HandshakeTimeout: time.Minute, QuickModeTimeout: time.Minute}, sas: map[Cookie]*controlSA{cookie: sa}}
	wire, _ := (Packet{InitiatorCookie: Cookie{1}, ResponderCookie: cookie, Exchange: ExchangeIdentityProtect}).MarshalBinary()
	peer4500 := &net.UDPAddr{IP: net.IPv4(198, 51, 100, 20), Port: 62000}
	if _, err := control.HandleNATTDatagram(peer4500, wire, time.Now()); !errors.Is(err, ErrUnexpectedExchange) {
		t.Fatalf("migration error=%v", err)
	}
	if sa.peer == addressKey(peer4500) {
		t.Fatal("failed authentication committed the migrated peer")
	}
	sa.responses[string(wire)] = []byte{1} // A cached response proves prior authentication.
	if _, err := control.HandleNATTDatagram(peer4500, wire, time.Now()); err != nil || sa.peer != addressKey(peer4500) {
		t.Fatalf("authenticated migration peer=%q error=%v", sa.peer, err)
	}
	wrongIP := &net.UDPAddr{IP: net.IPv4(198, 51, 100, 21), Port: 4500}
	if _, err := control.HandleNATTDatagram(wrongIP, wire, time.Now()); !errors.Is(err, ErrUnknownSA) {
		t.Fatalf("wrong-IP migration error=%v", err)
	}
}

func TestControlPlaneHalfOpenAndPerPeerLimits(t *testing.T) {
	sa := SecurityAssociation{DOI: DOIIPsec, Situation: SituationIdentityOnly, Proposals: []Proposal{{Number: 1, ProtocolID: ProtocolIKE, Transforms: []Transform{phase1Transform(EncryptionAESCBC, HashSHA1, DHGroup2, 128)}}}}
	request := func(cookie byte) []byte {
		wire, _ := (Packet{InitiatorCookie: Cookie{cookie}, Exchange: ExchangeIdentityProtect, Payloads: []Payload{sa}}).MarshalBinary()
		return wire
	}
	newControl := func(halfOpen, perPeer int) *ControlPlane {
		control, err := NewControlPlane(ControlPlaneConfig{PreSharedKey: []byte("psk"), ResponderID: Identification{IDType: IDIPv4Address, Data: []byte{192, 0, 2, 1}}, Random: bytes.NewReader(bytes.Repeat([]byte{0x55}, 1024)), MaxPhase1SAs: 10, MaxHalfOpen: halfOpen, MaxSAsPerPeer: perPeer})
		if err != nil {
			t.Fatal(err)
		}
		return control
	}
	now := time.Unix(1, 0)
	firstPeer := &net.UDPAddr{IP: net.IPv4(192, 0, 2, 10), Port: 500}
	otherPeer := &net.UDPAddr{IP: net.IPv4(192, 0, 2, 11), Port: 500}
	half := newControl(1, 0)
	_, _ = half.HandleDatagram(firstPeer, request(1), now)
	if _, err := half.HandleDatagram(otherPeer, request(2), now); !errors.Is(err, ErrSALimit) {
		t.Fatalf("half-open error=%v", err)
	}
	perPeer := newControl(0, 1)
	_, _ = perPeer.HandleDatagram(firstPeer, request(3), now)
	if _, err := perPeer.HandleDatagram(&net.UDPAddr{IP: firstPeer.IP, Port: 501}, request(4), now); !errors.Is(err, ErrSALimit) {
		t.Fatalf("per-peer error=%v", err)
	}
}

func TestControlPlaneSanitizedDebugTrace(t *testing.T) {
	var logs []string
	control, err := NewControlPlane(ControlPlaneConfig{PreSharedKey: []byte("super-secret-psk"), ResponderID: Identification{IDType: IDIPv4Address, Data: []byte{192, 0, 2, 1}}, Random: bytes.NewReader(bytes.Repeat([]byte{0x44}, 512)), Debugf: func(format string, args ...any) { logs = append(logs, fmt.Sprintf(format, args...)) }})
	if err != nil {
		t.Fatal(err)
	}
	sa := SecurityAssociation{DOI: DOIIPsec, Situation: SituationIdentityOnly, Proposals: []Proposal{{Number: 1, ProtocolID: ProtocolIKE, Transforms: []Transform{phase1Transform(EncryptionAESCBC, HashSHA1, DHGroup2, 128)}}}}
	wire, _ := (Packet{InitiatorCookie: Cookie{1}, Exchange: ExchangeIdentityProtect, Payloads: []Payload{sa}}).MarshalBinary()
	_, _ = control.HandleDatagram(&net.UDPAddr{IP: net.IPv4(192, 0, 2, 10), Port: 500}, wire, time.Now())
	joined := strings.Join(logs, "\n")
	if !strings.Contains(joined, "ike rx") || !strings.Contains(joined, "state=await-key-exchange") || strings.Contains(joined, "super-secret-psk") {
		t.Fatalf("logs=%q", joined)
	}
}
