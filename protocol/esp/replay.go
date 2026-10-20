package esp

// ReplayWindowSize preserves the zero-value window's 64-packet behavior.
const ReplayWindowSize = 64
const MaxReplayWindowSize = 1024

type ReplayWindow struct {
	highest uint64
	bitmap  [MaxReplayWindowSize / 64]uint64
	size    uint32
}

// NewReplayWindow creates a bounded window in whole 64-packet words. Zero
// selects the historical 64-packet default; invalid sizes fail explicitly.
func NewReplayWindow(size uint32) (ReplayWindow, error) {
	if size == 0 {
		size = ReplayWindowSize
	}
	if size < ReplayWindowSize || size > MaxReplayWindowSize || size%64 != 0 {
		return ReplayWindow{}, ErrInvalidPacket
	}
	return ReplayWindow{size: size}, nil
}

func (w *ReplayWindow) Size() uint32 {
	if w.size == 0 {
		return ReplayWindowSize
	}
	return w.size
}

func (w *ReplayWindow) Check(sequence uint32) error {
	if sequence == 0 {
		return ErrReplay
	}
	seq := uint64(sequence)
	if seq > w.highest {
		return nil
	}
	delta := w.highest - seq
	if delta >= uint64(w.Size()) || w.bitmap[delta/64]&(uint64(1)<<(delta%64)) != 0 {
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
		if shift >= uint64(w.Size()) {
			w.bitmap = [MaxReplayWindowSize / 64]uint64{}
		} else {
			words, bits := int(shift/64), uint(shift%64)
			// Work from high to low so reads never see an already shifted word.
			for i := int(w.Size()/64) - 1; i >= 0; i-- {
				var value uint64
				if j := i - words; j >= 0 {
					value = w.bitmap[j] << bits
					if bits != 0 && j > 0 {
						value |= w.bitmap[j-1] >> (64 - bits)
					}
				}
				w.bitmap[i] = value
			}
		}
		w.bitmap[0] |= 1
		w.highest = seq
		return nil
	}
	delta := w.highest - seq
	w.bitmap[delta/64] |= uint64(1) << (delta % 64)
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
	state := ReplayState{SPI: s.spi, Sequence: sequence, Highest: s.replay.Highest(), Window: s.replay.Size(), Reason: "acceptable"}
	if sequence == 0 {
		state.Reason = "zero_sequence"
	} else if sequence <= state.Highest && state.Highest-sequence >= state.Window {
		state.Reason = "outside_window"
	} else if s.replay.Check(sequence) != nil {
		state.Reason = "duplicate"
	}
	return state
}
