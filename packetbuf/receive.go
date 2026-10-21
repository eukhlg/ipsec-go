package packetbuf

// ReceiveSlot loans exclusively owned storage to a socket read. The read
// callback must write only received bytes, set N to their actual length, and
// return the number of populated slots. It must not retain Payload or mutate
// Buffer's bounds. Outside the callback, Payload is limited to valid data.
// Ordinary arbitrary writable access must use Bytes, Prepend or Append instead.
type ReceiveSlot struct {
	Buffer  *Buffer
	Payload []byte
	N       int
	owner   *Buffer
	offset  int
	limit   int
}

// Receive uses the socket's returned lengths rather than treating the entire
// read capacity as written. Previous writable exposures remain dirty. Errors,
// panics, invalid lengths and truncation (N beyond capacity) conservatively
// dirty the full loan. Slots after count are untouched on a successful read.
// This is a synchronous storage loan; it does not transfer buffer ownership.
func Receive(slots []ReceiveSlot, read func([]ReceiveSlot) (int, error)) (count int, err error) {
	for i := range slots {
		s := &slots[i]
		s.owner, s.offset, s.limit = s.Buffer, s.Buffer.start, s.Buffer.Len()
		s.Payload = s.Buffer.storage[s.Buffer.start:s.Buffer.end:s.Buffer.end]
		s.N = 0
	}
	returned := false
	defer func() {
		validCount := count >= 0 && count <= len(slots)
		for i := range slots {
			s := &slots[i]
			n := s.limit
			if returned && err == nil && validCount {
				if i >= count {
					n = 0
				} else if s.N >= 0 && s.N <= n {
					n = s.N
				}
			}
			s.owner.expose(s.offset, s.offset+n)
			if returned && validCount && i < count && s.N >= 0 && s.N <= s.limit {
				s.owner.end = s.offset + s.N
				s.Payload = s.owner.storage[s.offset:s.owner.end:s.owner.end]
			} else {
				// Unpopulated or invalid outputs are not packet views.
				s.Payload = nil
			}
			s.owner = nil
		}
		if !validCount {
			count, err = 0, ErrSize
		}
	}()
	count, err = read(slots)
	returned = true
	return
}
