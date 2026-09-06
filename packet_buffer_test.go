package connectip

import (
	"context"
	"encoding/binary"
	"errors"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/metacubex/quic-go"
	"github.com/metacubex/quic-go/quicvarint"
	"github.com/stretchr/testify/require"
)

type packetBufferTestStream struct {
	bufferQueue []*quic.DatagramBuffer
	tryQueue    []*quic.DatagramBuffer
	sendErr     error
	ownedCalls  int
	sent        [][]byte
}

func (s *packetBufferTestStream) Read([]byte) (int, error)        { return 0, nil }
func (s *packetBufferTestStream) Write(p []byte) (int, error)     { return len(p), nil }
func (s *packetBufferTestStream) Close() error                    { return nil }
func (s *packetBufferTestStream) CancelRead(quic.StreamErrorCode) {}
func (s *packetBufferTestStream) SendDatagram(p []byte) error {
	s.sent = append(s.sent, append([]byte(nil), p...))
	return s.sendErr
}
func (s *packetBufferTestStream) ReceiveDatagram(context.Context) ([]byte, error) {
	return nil, context.Canceled
}
func (s *packetBufferTestStream) SetDeadline(time.Time) error      { return nil }
func (s *packetBufferTestStream) SetReadDeadline(time.Time) error  { return nil }
func (s *packetBufferTestStream) SetWriteDeadline(time.Time) error { return nil }
func (s *packetBufferTestStream) Context() context.Context         { return context.Background() }

func (s *packetBufferTestStream) ReceiveDatagramBuffer(context.Context) (*quic.DatagramBuffer, error) {
	if len(s.bufferQueue) == 0 {
		return nil, context.Canceled
	}
	b := s.bufferQueue[0]
	s.bufferQueue = s.bufferQueue[1:]
	return b, nil
}
func (s *packetBufferTestStream) TryReceiveDatagramBuffer() (*quic.DatagramBuffer, error) {
	if len(s.tryQueue) == 0 {
		return nil, context.Canceled
	}
	b := s.tryQueue[0]
	s.tryQueue = s.tryQueue[1:]
	return b, nil
}
func (s *packetBufferTestStream) SendDatagramBuffer([]byte, int, int) error { return s.sendErr }
func (s *packetBufferTestStream) SendDatagramBufferOwned([]byte, int, int, quic.DatagramPayloadOwner) error {
	s.ownedCalls++
	return s.sendErr
}

type packetBufferTestOwner struct{ releases atomic.Int32 }

func (o *packetBufferTestOwner) Release() { o.releases.Add(1) }

func packetBufferTestConn(s http3Stream) *Conn {
	c := newProxiedConn(s, nil)
	c.peerAddresses = []netip.Prefix{netip.MustParsePrefix("192.168.0.10/32")}
	c.localRoutes = []IPRoute{{StartIP: netip.MustParseAddr("10.0.0.0"), EndIP: netip.MustParseAddr("10.0.0.255")}}
	return c
}

func packetBufferTestIP() []byte {
	return []byte{0x45, 0, 0, 20, 0, 0, 0, 0, 64, 17, 0, 0, 192, 168, 0, 10, 10, 0, 0, 1}
}

func TestReadPacketBufferPreservesBorrowedHandle(t *testing.T) {
	raw := append(quicvarint.Append(nil, 0), packetBufferTestIP()...)
	b := &quic.DatagramBuffer{Data: raw}
	s := &packetBufferTestStream{bufferQueue: []*quic.DatagramBuffer{b}}
	p, err := packetBufferTestConn(s).ReadPacketBuffer()
	require.NoError(t, err)
	require.Same(t, b, (*quic.DatagramBuffer)(p))
	require.Equal(t, raw[1:], p.Data)
	p.Release()
	require.Nil(t, b.Data)
}

func TestTryReadPacketBufferReleasesUnsupportedDatagram(t *testing.T) {
	bad := &quic.DatagramBuffer{Data: quicvarint.Append(nil, 1)}
	raw := append(quicvarint.Append(nil, 0), packetBufferTestIP()...)
	good := &quic.DatagramBuffer{Data: raw}
	s := &packetBufferTestStream{tryQueue: []*quic.DatagramBuffer{bad, good}}
	p, err := packetBufferTestConn(s).TryReadPacketBuffer()
	require.NoError(t, err)
	require.Nil(t, bad.Data)
	p.Release()
	require.Nil(t, good.Data)
}

func TestWritePacketBufferOwnedTransfersOnlyOnAcceptedSend(t *testing.T) {
	s := &packetBufferTestStream{}
	c := newProxiedConn(s, nil)
	ip := packetBufferTestIP()
	buf := make([]byte, len(ip)+1)
	copy(buf[1:], ip)
	o := new(packetBufferTestOwner)
	_, err := c.WritePacketBufferOwned(buf, 1, len(ip), o)
	require.NoError(t, err)
	require.Equal(t, 1, s.ownedCalls)
	require.Zero(t, o.releases.Load())
}

func TestWritePacketBufferOwnedReleasesOnError(t *testing.T) {
	s := &packetBufferTestStream{sendErr: errors.New("send failed")}
	c := newProxiedConn(s, nil)
	ip := packetBufferTestIP()
	buf := make([]byte, len(ip)+1)
	copy(buf[1:], ip)
	o := new(packetBufferTestOwner)
	_, err := c.WritePacketBufferOwned(buf, 1, len(ip), o)
	require.Error(t, err)
	require.EqualValues(t, 1, o.releases.Load())
}

func TestWritePacketBufferRejectsInsufficientHeadroom(t *testing.T) {
	c := newProxiedConn(&packetBufferTestStream{}, nil)
	_, err := c.WritePacketBuffer(make([]byte, 20), 0, 20)
	require.ErrorContains(t, err, "invalid packet buffer range")
}

type legacyPacketStream struct {
	sent    [][]byte
	sendErr error
}

func (s *legacyPacketStream) Read([]byte) (int, error)        { return 0, context.Canceled }
func (s *legacyPacketStream) Write(p []byte) (int, error)     { return len(p), nil }
func (s *legacyPacketStream) Close() error                    { return nil }
func (s *legacyPacketStream) CancelRead(quic.StreamErrorCode) {}
func (s *legacyPacketStream) ReceiveDatagram(context.Context) ([]byte, error) {
	return nil, context.Canceled
}
func (s *legacyPacketStream) SendDatagram(p []byte) error {
	s.sent = append(s.sent, append([]byte(nil), p...))
	return s.sendErr
}
func (s *legacyPacketStream) SetDeadline(time.Time) error      { return nil }
func (s *legacyPacketStream) SetReadDeadline(time.Time) error  { return nil }
func (s *legacyPacketStream) SetWriteDeadline(time.Time) error { return nil }
func (s *legacyPacketStream) Context() context.Context         { return context.Background() }

func packetBufferTestIPWithOptions() []byte {
	b := append([]byte(nil), packetBufferTestIP()...)
	b[0] = 0x46 // IPv4, IHL 6: one 4-byte options word.
	b[2], b[3] = 0, 24
	b = append(b, 0x01, 0x02, 0x03, 0x04)
	return b
}

func assertPreparedIPv4Options(t *testing.T, data, original []byte) {
	t.Helper()
	require.Len(t, data, len(original)+1)
	require.Equal(t, byte(0), data[0])
	require.Equal(t, byte(4), data[1]>>4)
	require.Equal(t, original[0]&0x0f, data[1]&0x0f)
	require.Equal(t, original[8]-1, data[9])
	require.Equal(t, original[20:], data[21:])
	gotChecksum := binary.BigEndian.Uint16(data[11:13])
	withoutContext := append([]byte(nil), data[1:]...)
	withoutContext[10], withoutContext[11] = 0, 0
	require.Equal(t, gotChecksum, calculateIPv4ChecksumBytes(withoutContext[:int(withoutContext[0]&0x0f)*4]))
	require.Equal(t, original[12:20], data[13:21])
}

func TestIPv4OptionsChecksumAllWritePaths(t *testing.T) {
	for _, path := range []string{"write", "buffer", "owned"} {
		t.Run(path, func(t *testing.T) {
			ip := packetBufferTestIPWithOptions()
			want := append([]byte(nil), ip...)
			var s *legacyPacketStream
			var owner *packetBufferTestOwner
			var buf []byte
			var offset int
			if path == "write" {
				s = new(legacyPacketStream)
				_, err := (&Conn{str: s, closeChan: make(chan struct{})}).WritePacket(ip)
				require.NoError(t, err)
			} else {
				s = new(legacyPacketStream)
				offset = 9
				buf = make([]byte, offset+len(ip))
				copy(buf[offset:], ip)
				c := &Conn{str: s, closeChan: make(chan struct{})}
				if path == "owned" {
					owner = new(packetBufferTestOwner)
					_, err := c.WritePacketBufferOwned(buf, offset, len(ip), owner)
					require.NoError(t, err)
					require.EqualValues(t, 1, owner.releases.Load())
				} else {
					_, err := c.WritePacketBuffer(buf, offset, len(ip))
					require.NoError(t, err)
				}
			}
			require.Len(t, s.sent, 1)
			assertPreparedIPv4Options(t, s.sent[0], want)
		})
	}
}

func TestWritePacketBufferLegacyFallbackPreparesExactlyOnce(t *testing.T) {
	ip := packetBufferTestIPWithOptions()
	s := new(legacyPacketStream)
	buf := make([]byte, 9+len(ip))
	copy(buf[9:], ip)
	_, err := (&Conn{str: s, closeChan: make(chan struct{})}).WritePacketBuffer(buf, 9, len(ip))
	require.NoError(t, err)
	require.Len(t, s.sent, 1)
	assertPreparedIPv4Options(t, s.sent[0], ip)
}

func TestWritePacketBufferOwnedLegacyFallbackReleasesOnTooLarge(t *testing.T) {
	ip := packetBufferTestIPWithOptions()
	s := &legacyPacketStream{sendErr: &quic.DatagramTooLargeError{MaxDatagramPayloadSize: 1200}}
	buf := make([]byte, 9+len(ip))
	copy(buf[9:], ip)
	owner := new(packetBufferTestOwner)
	_, err := (&Conn{str: s, closeChan: make(chan struct{})}).WritePacketBufferOwned(buf, 9, len(ip), owner)
	require.NoError(t, err)
	require.EqualValues(t, 1, owner.releases.Load())
	require.Len(t, s.sent, 1)
}

func TestIPv4OptionsMalformedIHLDoesNotDecrementTTL(t *testing.T) {
	for _, ihl := range []byte{4, 7} {
		ip := packetBufferTestIP()
		ip[0] = 0x40 | ihl
		ttl := ip[8]
		_, err := (&Conn{}).composeDatagram(ip)
		require.Error(t, err)
		require.Equal(t, ttl, ip[8])
	}
}
