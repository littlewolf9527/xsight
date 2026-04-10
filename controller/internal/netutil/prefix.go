// Package netutil provides shared network utility functions.
package netutil

import (
	"fmt"
	"net"
)

// FormatPrefix converts raw IP bytes + prefix length to a CIDR string.
// e.g. ([]byte{10,2,0,0}, 24) → "10.2.0.0/24"
func FormatPrefix(raw []byte, prefixLen uint32) string {
	ip := net.IP(raw)
	if ip4 := ip.To4(); ip4 != nil {
		return fmt.Sprintf("%s/%d", ip4.String(), prefixLen)
	}
	return fmt.Sprintf("%s/%d", ip.String(), prefixLen)
}
