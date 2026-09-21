package connectip

import "encoding/binary"

const (
	ipv6FixedHeaderLen      = 40
	maxIPv6ExtensionHeaders = 8
	maxIPv6ExtensionBytes   = 256

	ipProtoHopByHop     = 0
	ipProtoRouting      = 43
	ipProtoFragment     = 44
	ipProtoESP          = 50
	ipProtoAH           = 51
	ipProtoNoNextHeader = 59
	ipProtoDestination  = 60
)

type ipv6ProxiedInfo struct {
	protocol uint8
}

// parseIPv6ProxiedPacket validates a complete non-jumbogram IPv6 packet and
// returns its upper-layer protocol without allocating. Non-first fragments
// use the Fragment header's Next Header value: their fragmentable payload
// doesn't guarantee that another extension or transport header is present.
func parseIPv6ProxiedPacket(packet []byte) (ipv6ProxiedInfo, bool) {
	if len(packet) < ipv6FixedHeaderLen || packet[0]>>4 != 6 {
		return ipv6ProxiedInfo{}, false
	}
	payloadLen := int(binary.BigEndian.Uint16(packet[4:6]))
	// Payload Length zero would require parsing a Jumbo Payload option. This
	// transport intentionally doesn't support IPv6 jumbograms.
	if payloadLen == 0 || payloadLen+ipv6FixedHeaderLen != len(packet) {
		return ipv6ProxiedInfo{}, false
	}

	next := packet[6]
	offset := ipv6FixedHeaderLen
	extBytes := 0
	for count := 0; count < maxIPv6ExtensionHeaders; count++ {
		var length int
		switch next {
		case ipProtoHopByHop, ipProtoRouting, ipProtoDestination:
			if offset+2 > len(packet) {
				return ipv6ProxiedInfo{}, false
			}
			length = (int(packet[offset+1]) + 1) * 8
		case ipProtoFragment:
			if offset+8 > len(packet) {
				return ipv6ProxiedInfo{}, false
			}
			fragmentNext := packet[offset]
			fragmentOffset := binary.BigEndian.Uint16(packet[offset+2:offset+4]) & 0xfff8
			if fragmentOffset != 0 {
				return ipv6ProxiedInfo{protocol: fragmentNext}, true
			}
			length = 8
		case ipProtoAH:
			if offset+2 > len(packet) || packet[offset+1] < 1 {
				return ipv6ProxiedInfo{}, false
			}
			length = (int(packet[offset+1]) + 2) * 4
		case ipProtoESP, ipProtoNoNextHeader:
			return ipv6ProxiedInfo{protocol: next}, true
		default:
			return ipv6ProxiedInfo{protocol: next}, true
		}
		if length < 8 || offset+length > len(packet) {
			return ipv6ProxiedInfo{}, false
		}
		extBytes += length
		if extBytes > maxIPv6ExtensionBytes {
			return ipv6ProxiedInfo{}, false
		}
		next = packet[offset]
		offset += length
	}
	// A ninth recognized extension header exceeds the bounded parser budget.
	switch next {
	case ipProtoHopByHop, ipProtoRouting, ipProtoFragment, ipProtoAH, ipProtoDestination:
		return ipv6ProxiedInfo{}, false
	default:
		return ipv6ProxiedInfo{protocol: next}, true
	}
}
