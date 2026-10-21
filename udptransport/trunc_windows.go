package udptransport

// Winsock returns WSAEMSGSIZE on truncation; Read rejects that error.
func messageTruncated(flags int) bool { return flags&0x0100 != 0 }
