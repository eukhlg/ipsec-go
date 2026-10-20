package esp

const ReplayWindowSize = 64

type ReplayWindow struct{ highest, bitmap uint64 }

func (w *ReplayWindow) Check(sequence uint32) error {
	if sequence == 0 {
		return ErrReplay
	}
	seq := uint64(sequence)
	if seq > w.highest {
		return nil
	}
	delta := w.highest - seq
	if delta >= ReplayWindowSize || w.bitmap&(uint64(1)<<delta) != 0 {
		return ErrReplay
	}
	return nil
}

func (w *ReplayWindow) Accept(sequence uint32) error {
	if err := w.Check(sequence); err != nil {
		return err
	}
	seq := uint64(sequence)
	if seq > w.highest {
		shift := seq - w.highest
		if shift >= ReplayWindowSize {
			w.bitmap = 1
		} else {
			w.bitmap = w.bitmap<<shift | 1
		}
		w.highest = seq
		return nil
	}
	w.bitmap |= uint64(1) << (w.highest - seq)
	return nil
}

func (w ReplayWindow) Highest() uint32 { return uint32(w.highest) }

// ReplayState describes a sequence relative to the current receive window.
// It is diagnostic only: a replay precheck rejection does not authenticate
// the rejected packet, and inspecting state must never advance the window.
type ReplayState struct {
	SPI, Sequence, Highest, Window uint32
	Reason                         string
}

func (s *SA) ReplayState(sequence uint32) ReplayState {
	s.mu.Lock()
	defer s.mu.Unlock()
	state := ReplayState{SPI: s.spi, Sequence: sequence, Highest: s.replay.Highest(), Window: ReplayWindowSize, Reason: "acceptable"}
	if sequence == 0 {
		state.Reason = "zero_sequence"
	} else if sequence <= state.Highest && state.Highest-sequence >= ReplayWindowSize {
		state.Reason = "outside_window"
	} else if s.replay.Check(sequence) != nil {
		state.Reason = "duplicate"
	}
	return state
}
