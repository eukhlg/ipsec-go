package esp

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
	if delta >= 64 || w.bitmap&(uint64(1)<<delta) != 0 {
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
		if shift >= 64 {
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
