package connectip

import (
	"encoding/binary"
	"testing"

	"github.com/stretchr/testify/require"
)

func makeIPv6TestPacket(next uint8, payload []byte) []byte {
	p := make([]byte, ipv6FixedHeaderLen+len(payload))
	p[0] = 0x60
	binary.BigEndian.PutUint16(p[4:6], uint16(len(payload)))
	p[6], p[7] = next, 64
	p[23], p[39] = 1, 2
	copy(p[40:], payload)
	return p
}

func TestParseIPv6ProxiedPacketExtensionsAndTerminalProtocols(t *testing.T) {
	tests := []struct {
		name    string
		next    uint8
		payload []byte
		want    uint8
	}{
		{"hop by hop", ipProtoHopByHop, []byte{6, 0, 0, 0, 0, 0, 0, 0}, 6},
		{"routing", ipProtoRouting, []byte{6, 0, 0, 0, 0, 0, 0, 0}, 6},
		{"destination options", ipProtoDestination, []byte{6, 0, 0, 0, 0, 0, 0, 0}, 6},
		{"fragment first", ipProtoFragment, []byte{6, 0, 0, 0, 0, 0, 0, 1}, 6},
		{"fragment non-first", ipProtoFragment, []byte{6, 0, 0, 8, 0, 0, 0, 1}, 6},
		{"AH", ipProtoAH, []byte{6, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, 6},
		{"ESP opaque", ipProtoESP, []byte{1, 2, 3}, ipProtoESP},
		{"no next header", ipProtoNoNextHeader, []byte{0}, ipProtoNoNextHeader},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := parseIPv6ProxiedPacket(makeIPv6TestPacket(tt.next, tt.payload))
			require.True(t, ok)
			require.Equal(t, tt.want, got.protocol)
		})
	}
}

func TestParseIPv6ProxiedPacketRejectsMalformedLengthsAndChains(t *testing.T) {
	tests := []struct {
		name string
		make func() []byte
	}{
		{"jumbogram unsupported", func() []byte { return makeIPv6TestPacket(17, nil) }},
		{"trailing bytes", func() []byte {
			p := makeIPv6TestPacket(17, []byte{1})
			return append(p, 2)
		}},
		{"truncated payload", func() []byte {
			p := makeIPv6TestPacket(17, []byte{1, 2})
			return p[:len(p)-1]
		}},
		{"truncated extension", func() []byte { return makeIPv6TestPacket(ipProtoHopByHop, []byte{17}) }},
		{"invalid AH length", func() []byte { return makeIPv6TestPacket(ipProtoAH, []byte{17, 0, 0, 0, 0, 0, 0, 0}) }},
		{"too many extensions", func() []byte {
			payload := make([]byte, 9*8)
			for i := 0; i < 9; i++ {
				payload[i*8] = ipProtoDestination
			}
			payload[8*8] = 17
			return makeIPv6TestPacket(ipProtoDestination, payload)
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, ok := parseIPv6ProxiedPacket(tt.make())
			require.False(t, ok)
		})
	}
}

func BenchmarkParseIPv6ProxiedPacket(b *testing.B) {
	plain := makeIPv6TestPacket(6, make([]byte, 20))
	extension := makeIPv6TestPacket(ipProtoDestination, append([]byte{6, 0, 0, 0, 0, 0, 0, 0}, make([]byte, 20)...))
	for _, tc := range []struct {
		name string
		data []byte
	}{{"plain", plain}, {"destination-options", extension}} {
		b.Run(tc.name, func(b *testing.B) {
			b.ReportAllocs()
			for range b.N {
				if _, ok := parseIPv6ProxiedPacket(tc.data); !ok {
					b.Fatal("unexpected parse failure")
				}
			}
		})
	}
}
