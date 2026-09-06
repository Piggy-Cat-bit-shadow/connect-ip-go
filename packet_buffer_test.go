package connectip

import (
	"context"
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
}

func (s *packetBufferTestStream) Read([]byte) (int, error)        { return 0, nil }
func (s *packetBufferTestStream) Write(p []byte) (int, error)     { return len(p), nil }
func (s *packetBufferTestStream) Close() error                    { return nil }
func (s *packetBufferTestStream) CancelRead(quic.StreamErrorCode) {}
func (s *packetBufferTestStream) SendDatagram([]byte) error       { return s.sendErr }
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
