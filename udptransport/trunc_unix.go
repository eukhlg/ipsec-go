//go:build !linux && !windows

package udptransport

import "syscall"

func messageTruncated(flags int) bool { return flags&syscall.MSG_TRUNC != 0 }
