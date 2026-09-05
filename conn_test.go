package connectip

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"

	"github.com/metacubex/quic-go"
	"github.com/metacubex/quic-go/quicvarint"

	"github.com/stretchr/testify/require"
)

var ipv6Header = []byte{
	0x60, 0x00, 0x00, 0x00, // Version, Traffic Class, Flow Label
	0x00, 0x20, 59, 64, // Payload Length, Next Header, Hop Limit
	0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, // Source IP
	0x20, 0x01, 0x0d, 0xb8, 0x85, 0xa3, 0x08, 0xd3, 0x13, 0x19, 0x8a, 0x2e, 0x03, 0x70, 0x73, 0x48, // Destination IP
}

type mockStream struct {
	reading           []byte
	toRead            <-chan []byte
	sendDatagramErr   error
	sentDatagrams     [][]byte
	receivedDatagrams [][]byte
	receiveCalls      int
	receiveErr        error
}

var _ http3Stream = &mockStream{}

func (m *mockStream) StreamID() quic.StreamID { panic("implement me") }
func (m *mockStream) Read(p []byte) (int, error) {
	if m.reading == nil {
		m.reading = <-m.toRead
	}
	n := copy(p, m.reading)
	m.reading = m.reading[n:]
	return n, nil
}
func (m *mockStream) CancelRead(quic.StreamErrorCode)   {}
func (m *mockStream) Write(p []byte) (n int, err error) { return len(p), nil }
func (m *mockStream) Close() error                      { return nil }
func (m *mockStream) CancelWrite(quic.StreamErrorCode)  {}
func (m *mockStream) Context() context.Context          { return context.Background() }
func (m *mockStream) SetWriteDeadline(time.Time) error  { return nil }
func (m *mockStream) SetReadDeadline(time.Time) error   { return nil }
func (m *mockStream) SetDeadline(time.Time) error       { return nil }
func (m *mockStream) SendDatagram(data []byte) error {
	m.sentDatagrams = append(m.sentDatagrams, data)
	return m.sendDatagramErr
}
func (m *mockStream) ReceiveDatagram(ctx context.Context) ([]byte, error) {
	m.receiveCalls++
	if len(m.receivedDatagrams) > 0 {
		data := m.receivedDatagrams[0]
		m.receivedDatagrams = m.receivedDatagrams[1:]
		return data, nil
	}
	if m.receiveErr != nil {
		return nil, m.receiveErr
	}
	<-ctx.Done()
	return nil, ctx.Err()
}

type mockReceiveBufferStream struct {
	mockStream
	bufferDatagrams [][]byte
	bufferObjects   []*quic.DatagramBuffer
	bufferCalls     int
}

func (m *mockReceiveBufferStream) ReceiveDatagramBuffer(ctx context.Context) (*quic.DatagramBuffer, error) {
	m.bufferCalls++
	if len(m.bufferObjects) > 0 {
		buffer := m.bufferObjects[0]
		m.bufferObjects = m.bufferObjects[1:]
		return buffer, nil
	}
	if len(m.bufferDatagrams) > 0 {
		data := m.bufferDatagrams[0]
		m.bufferDatagrams = m.bufferDatagrams[1:]
		return &quic.DatagramBuffer{Data: data}, nil
	}
	if m.receiveErr != nil {
		return nil, m.receiveErr
	}
	<-ctx.Done()
	return nil, ctx.Err()
}

func incomingIPv4Packet() []byte {
	data, err := (&ipv4.Header{
		Version:  4,
		Len:      20,
		TTL:      64,
		Src:      net.IPv4(192, 168, 0, 10),
		Dst:      net.IPv4(10, 0, 0, 1),
		Protocol: 17,
	}).Marshal()
	if err != nil {
		panic(err)
	}
	return data
}

func newReceiveTestConn(str http3Stream) *Conn {
	conn := newProxiedConn(str)
	conn.peerAddresses = []netip.Prefix{netip.MustParsePrefix("192.168.0.10/32")}
	conn.localRoutes = []IPRoute{{StartIP: netip.MustParseAddr("10.0.0.0"), EndIP: netip.MustParseAddr("10.0.0.255")}}
	return conn
}

func newBareConn(str http3Stream) *Conn {
	return &Conn{
		str:                   str,
		writes:                make(chan writeCapsule),
		assignedAddressNotify: make(chan struct{}, 1),
		availableRoutesNotify: make(chan struct{}, 1),
		closeChan:             make(chan struct{}),
	}
}

func TestReadPacketBufferDropsInvalidThenReceivesNext(t *testing.T) {
	valid := append(quicvarint.Append(nil, 0), incomingIPv4Packet()...)
	str := &mockReceiveBufferStream{bufferDatagrams: [][]byte{{0, 0x50}, valid}}
	conn := newReceiveTestConn(str)

	p, err := conn.ReadPacketBuffer()
	require.NoError(t, err)
	require.Equal(t, incomingIPv4Packet(), p.Data)
	require.Equal(t, 2, str.bufferCalls)
	p.Release()
}

type benchmarkReceiveBufferStream struct {
	mockStream
	data []byte
}

func (s *benchmarkReceiveBufferStream) ReceiveDatagramBuffer(context.Context) (*quic.DatagramBuffer, error) {
	return &quic.DatagramBuffer{Data: s.data}, nil
}

func BenchmarkReadPacketBufferBorrowed(b *testing.B) {
	data := append(quicvarint.Append(nil, 0), incomingIPv4Packet()...)
	conn := newReceiveTestConn(&benchmarkReceiveBufferStream{data: data})
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		packet, err := conn.ReadPacketBuffer()
		if err != nil {
			b.Fatal(err)
		}
		packet.Release()
	}
}

func TestPacketBufferIsQuicDatagramBufferView(t *testing.T) {
	quicBuffer := &quic.DatagramBuffer{Data: []byte("payload")}
	packet := (*PacketBuffer)(quicBuffer)
	require.Same(t, quicBuffer, (*quic.DatagramBuffer)(packet))
	packet.Release()
	packet.Release()
	require.Nil(t, quicBuffer.Data)
}

func TestReadPacketBufferBorrowedReslicesSameHandle(t *testing.T) {
	raw := append(quicvarint.Append(nil, 0), incomingIPv4Packet()...)
	quicBuffer := &quic.DatagramBuffer{Data: raw}
	str := &mockReceiveBufferStream{bufferObjects: []*quic.DatagramBuffer{quicBuffer}}
	conn := newReceiveTestConn(str)

	packet, err := conn.ReadPacketBuffer()
	require.NoError(t, err)
	require.Same(t, quicBuffer, (*quic.DatagramBuffer)(packet))
	require.Equal(t, raw[1:], packet.Data)
	require.Same(t, &raw[1], &packet.Data[0])
	packet.Release()
	require.Nil(t, quicBuffer.Data)
}

func TestReadPacketBufferStalePacketRegression(t *testing.T) {
	secondReceive := errors.New("second receive")
	str := &mockStream{receivedDatagrams: [][]byte{{0, 0x50}}, receiveErr: secondReceive}
	conn := newReceiveTestConn(str)

	_, err := conn.ReadPacketBuffer()
	require.ErrorIs(t, err, secondReceive)
	require.Equal(t, 2, str.receiveCalls)
}

func TestReadPacketBufferIteratesUnsupportedContexts(t *testing.T) {
	const unsupported = 10000
	str := &mockStream{receivedDatagrams: make([][]byte, 0, unsupported+1)}
	for i := 0; i < unsupported; i++ {
		str.receivedDatagrams = append(str.receivedDatagrams, quicvarint.Append(nil, 1))
	}
	valid := append(quicvarint.Append(nil, 0), incomingIPv4Packet()...)
	str.receivedDatagrams = append(str.receivedDatagrams, valid)
	conn := newReceiveTestConn(str)

	p, err := conn.ReadPacketBuffer()
	require.NoError(t, err)
	require.Equal(t, unsupported+1, str.receiveCalls)
	p.Release()
}

func TestTryReadPacketBufferUnsupportedOnlyReturnsCanceled(t *testing.T) {
	str := &mockStream{receivedDatagrams: [][]byte{quicvarint.Append(nil, 1)}}
	conn := newReceiveTestConn(str)

	_, err := conn.TryReadPacketBuffer()
	require.ErrorIs(t, err, context.Canceled)
	require.Equal(t, 2, str.receiveCalls)
}

func TestReadPacketBufferLegacyFallbackKeepsIPv4Payload(t *testing.T) {
	ip := incomingIPv4Packet()
	raw := append(quicvarint.Append(nil, 0), ip...)
	str := &mockStream{receivedDatagrams: [][]byte{raw}}
	conn := newReceiveTestConn(str)

	p, err := conn.ReadPacketBuffer()
	require.NoError(t, err)
	require.Equal(t, ip, p.Data)
	require.Equal(t, &raw[1], &p.Data[0], "legacy fallback must return a reslice, not parse a second time")
	p.Release()
}

func TestReadPacketBufferLegacyFallbackKeepsIPv6Payload(t *testing.T) {
	ip := append([]byte(nil), ipv6Header...)
	dst := netip.MustParseAddr("2001:db8:1::1").As16()
	copy(ip[24:40], dst[:])
	raw := append(quicvarint.Append(nil, 0), ip...)
	str := &mockStream{receivedDatagrams: [][]byte{raw}}
	conn := newProxiedConn(str)
	conn.peerAddresses = []netip.Prefix{netip.MustParsePrefix("2001:db8::1/128")}
	conn.localRoutes = []IPRoute{{StartIP: netip.MustParseAddr("2001:db8:1::"), EndIP: netip.MustParseAddr("2001:db8:1::ffff")}}

	p, err := conn.ReadPacketBuffer()
	require.NoError(t, err)
	require.Equal(t, ip, p.Data)
	p.Release()
}

func TestReadPacketBufferMalformedContextReleasesAndReturnsError(t *testing.T) {
	str := &mockReceiveBufferStream{bufferDatagrams: [][]byte{{0xff}}}
	conn := newReceiveTestConn(str)

	_, err := conn.ReadPacketBuffer()
	require.ErrorContains(t, err, "connect-ip: malformed datagram")
	require.Equal(t, 1, str.bufferCalls)
}

func TestReadPacketBufferMapsTerminalTransportError(t *testing.T) {
	underlying := &quic.StreamError{Remote: true, ErrorCode: 42}
	conn := &Conn{
		str:       &mockReceiveBufferStream{mockStream: mockStream{receiveErr: underlying}},
		closeChan: make(chan struct{}),
	}

	_, err := conn.ReadPacketBuffer()
	var closeErr *CloseError
	require.ErrorAs(t, err, &closeErr)
	require.True(t, closeErr.Remote)
	require.ErrorIs(t, err, net.ErrClosed)
	require.NotEqual(t, underlying, err)
}

func TestReadPacketBufferPreservesNonTerminalErrors(t *testing.T) {
	sentinel := errors.New("sentinel")
	conn := &Conn{
		str:       &mockReceiveBufferStream{mockStream: mockStream{receiveErr: sentinel}},
		closeChan: make(chan struct{}),
	}

	_, err := conn.ReadPacketBuffer()
	require.ErrorIs(t, err, sentinel)
	var closeErr *CloseError
	require.NotErrorAs(t, err, &closeErr)
}

func TestReadPacketBufferLocalCloseWinsOverUnderlyingError(t *testing.T) {
	conn := &Conn{
		str:       &mockReceiveBufferStream{mockStream: mockStream{receiveErr: &quic.StreamError{Remote: false, ErrorCode: 42}}},
		closeChan: make(chan struct{}),
	}
	conn.markClosed(false)

	_, err := conn.ReadPacketBuffer()
	var closeErr *CloseError
	require.ErrorAs(t, err, &closeErr)
	require.False(t, closeErr.Remote)
}

func TestCloseIsIdempotentAndKeepsLocalState(t *testing.T) {
	conn := &Conn{
		str:       &mockStream{},
		closeChan: make(chan struct{}),
	}
	require.NoError(t, conn.Close())
	require.NoError(t, conn.Close())
	closeErr, ok := conn.closedError().(*CloseError)
	require.True(t, ok)
	require.False(t, closeErr.Remote)
}

func TestIncomingDatagrams(t *testing.T) {
	t.Run("empty packets", func(t *testing.T) {
		conn := newProxiedConn(&mockStream{})
		require.ErrorContains(t,
			conn.handleIncomingProxiedPacket([]byte{}),
			"connect-ip: empty packet",
		)
	})

	t.Run("invalid IP version", func(t *testing.T) {
		conn := newProxiedConn(&mockStream{})
		data := make([]byte, 20)
		data[0] = 5 << 4 // IPv5
		require.ErrorContains(t,
			conn.handleIncomingProxiedPacket(data),
			"connect-ip: unknown IP versions: 5",
		)
	})

	t.Run("IPv4 packet too short", func(t *testing.T) {
		conn := newProxiedConn(&mockStream{})
		data, err := (&ipv4.Header{
			Src:      net.IPv4(1, 2, 3, 4),
			Dst:      net.IPv4(159, 70, 42, 98),
			Len:      20,
			Checksum: 89,
		}).Marshal()
		require.NoError(t, err)
		require.ErrorContains(t,
			conn.handleIncomingProxiedPacket(data[:ipv4.HeaderLen-1]),
			"connect-ip: malformed datagram: too short",
		)
	})

	t.Run("IPv6 packet too short", func(t *testing.T) {
		conn := newProxiedConn(&mockStream{})
		require.ErrorContains(t,
			conn.handleIncomingProxiedPacket(ipv6Header[:ipv6.HeaderLen-1]),
			"connect-ip: malformed datagram: too short",
		)
	})

	t.Run("invalid source address", func(t *testing.T) {
		conn := newProxiedConn(&mockStream{})
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		require.NoError(t, conn.AssignAddresses(ctx, []netip.Prefix{netip.MustParsePrefix("192.168.0.10/32")}))
		hdr := &ipv4.Header{
			Src:      net.IPv4(192, 168, 0, 11),
			Dst:      net.IPv4(159, 70, 42, 98),
			Len:      20,
			Checksum: 89,
		}
		data, err := hdr.Marshal()
		require.NoError(t, err)
		require.ErrorContains(t,
			conn.handleIncomingProxiedPacket(data),
			"connect-ip: datagram source address not allowed: 192.168.0.11",
		)
	})

	t.Run("invalid destination address", func(t *testing.T) {
		conn := newProxiedConn(&mockStream{})
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		require.NoError(t, conn.AssignAddresses(ctx, []netip.Prefix{netip.MustParsePrefix("192.168.0.10/32")}))
		require.NoError(t, conn.AdvertiseRoute(ctx, []IPRoute{
			{StartIP: netip.MustParseAddr("10.0.0.0"), EndIP: netip.MustParseAddr("10.1.2.3")},
		}))
		hdr := &ipv4.Header{
			Src:      net.IPv4(192, 168, 0, 10),
			Dst:      net.IPv4(10, 1, 2, 3),
			Len:      20,
			Checksum: 89,
		}
		data, err := hdr.Marshal()
		require.NoError(t, err)
		require.NoError(t, conn.handleIncomingProxiedPacket(data))

		// 10.1.2.4 is outside the range of allowed addresses
		hdr.Dst = net.IPv4(10, 1, 2, 4)
		data, err = hdr.Marshal()
		require.NoError(t, err)
		require.ErrorContains(t,
			conn.handleIncomingProxiedPacket(data),
			"connect-ip: datagram destination address / protocol not allowed: 10.1.2.4 (protocol: 0)",
		)
	})

	t.Run("invalid IP protocol", func(t *testing.T) {
		conn := newProxiedConn(&mockStream{})
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		require.NoError(t, conn.AssignAddresses(ctx, []netip.Prefix{netip.MustParsePrefix("192.168.0.10/32")}))
		require.NoError(t, conn.AdvertiseRoute(ctx, []IPRoute{
			{StartIP: netip.MustParseAddr("10.0.0.0"), EndIP: netip.MustParseAddr("10.1.2.3"), IPProtocol: 42},
		}))
		hdr := &ipv4.Header{
			Src:      net.IPv4(192, 168, 0, 10),
			Dst:      net.IPv4(10, 1, 2, 3),
			Len:      20,
			Checksum: 89,
			Protocol: 42,
		}
		data, err := hdr.Marshal()
		require.NoError(t, err)
		require.NoError(t, conn.handleIncomingProxiedPacket(data))

		hdr.Protocol = 41
		data, err = hdr.Marshal()
		require.NoError(t, err)
		require.ErrorContains(t,
			conn.handleIncomingProxiedPacket(data),
			"connect-ip: datagram destination address / protocol not allowed: 10.1.2.3 (protocol: 41)",
		)

		// ICMP is always allowed
		hdr.Protocol = ipProtoICMP
		data, err = hdr.Marshal()
		require.NoError(t, err)
		require.NoError(t, conn.handleIncomingProxiedPacket(data))
	})

	t.Run("packet from assigned address", func(t *testing.T) {
		readChan := make(chan []byte, 1)
		conn := newProxiedConn(&mockStream{toRead: readChan})

		hdr := &ipv4.Header{
			Src:      net.IPv4(159, 70, 42, 98),
			Dst:      net.IPv4(192, 168, 0, 10),
			Len:      20,
			Checksum: 89,
		}
		data, err := hdr.Marshal()
		require.NoError(t, err)
		require.Error(t, conn.handleIncomingProxiedPacket(data), "connect-ip: datagram destination address")

		// now assign 192.168.0.11 to this connection
		readChan <- (&addressAssignCapsule{
			AssignedAddresses: []AssignedAddress{{IPPrefix: netip.MustParsePrefix("192.168.0.10/32")}},
		}).append(nil)

		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_, err = conn.LocalPrefixes(ctx)
		require.NoError(t, err)
		// after processing the address assignment, this is a valid packet
		require.NoError(t, conn.handleIncomingProxiedPacket(data))
	})
}

func TestSkipUnknownCapsule(t *testing.T) {
	readChan := make(chan []byte, 1)
	conn := newProxiedConn(&mockStream{toRead: readChan})

	data := quicvarint.Append(nil, 42)
	data = quicvarint.Append(data, 3)
	data = append(data, "foo"...)
	data = (&addressAssignCapsule{
		AssignedAddresses: []AssignedAddress{{IPPrefix: netip.MustParsePrefix("192.168.0.10/32")}},
	}).append(data)
	readChan <- data

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	prefixes, err := conn.LocalPrefixes(ctx)
	require.NoError(t, err)
	require.Equal(t, []netip.Prefix{netip.MustParsePrefix("192.168.0.10/32")}, prefixes)
}

func FuzzIncomingDatagram(f *testing.F) {
	conn := newProxiedConn(&mockStream{})
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	require.NoError(f, conn.AssignAddresses(ctx, []netip.Prefix{
		netip.MustParsePrefix("192.168.0.0/16"),
		netip.MustParsePrefix("2001:db8::0/64"),
	}))
	require.NoError(f, conn.AdvertiseRoute(ctx, []IPRoute{
		{StartIP: netip.MustParseAddr("10.0.0.0"), EndIP: netip.MustParseAddr("10.1.2.3"), IPProtocol: 42},
		{StartIP: netip.MustParseAddr("2001:db8:1::"), EndIP: netip.MustParseAddr("2001:db8:1::ffff"), IPProtocol: 42},
	}))

	ipv4Header, err := (&ipv4.Header{
		Src:      net.IPv4(1, 2, 3, 4),
		Dst:      net.IPv4(159, 70, 42, 98),
		Len:      20,
		Checksum: 89,
	}).Marshal()
	require.NoError(f, err)

	f.Add(ipv4Header)
	f.Add(ipv6Header)

	f.Fuzz(func(t *testing.T, data []byte) {
		conn.handleIncomingProxiedPacket(data)
	})
}

func TestSendingDatagrams(t *testing.T) {
	t.Run("invalid IP version", func(t *testing.T) {
		conn := newProxiedConn(&mockStream{})
		data := make([]byte, 20)
		data[0] = 5 << 4 // IPv5
		_, err := conn.composeDatagram(data)
		require.ErrorContains(t, err, "connect-ip: unknown IP versions: 5")
	})

	t.Run("IPv4 packet too short", func(t *testing.T) {
		conn := newProxiedConn(&mockStream{})
		data, err := (&ipv4.Header{
			Src:      net.IPv4(1, 2, 3, 4),
			Dst:      net.IPv4(159, 70, 42, 98),
			Len:      20,
			Checksum: 89,
		}).Marshal()
		require.NoError(t, err)
		_, err = conn.composeDatagram(data[:ipv4.HeaderLen-1])
		require.ErrorContains(t, err, "connect-ip: IPv4 packet too short")
	})

	t.Run("IPv6 packet too short", func(t *testing.T) {
		conn := newProxiedConn(&mockStream{})
		_, err := conn.composeDatagram(ipv6Header[:ipv6.HeaderLen-1])
		require.ErrorContains(t, err, "connect-ip: IPv6 packet too short")
	})
}

func TestSendLargeDatagrams(t *testing.T) {
	str := &mockStream{sendDatagramErr: &quic.DatagramTooLargeError{}}
	conn := newProxiedConn(str)
	data, err := (&ipv4.Header{
		Version:  4,
		Len:      20,
		TTL:      64,
		Src:      net.IPv4(1, 2, 3, 4),
		Dst:      net.IPv4(5, 6, 7, 8),
		Protocol: 17,
	}).Marshal()
	require.NoError(t, err)
	icmp, err := conn.WritePacket(data)
	require.NoError(t, err)
	require.NotNil(t, icmp)
}

type mockBufferStream struct {
	mockStream
	buffer      []byte
	offset      int
	length      int
	bufferCalls int
}

type mockOwnedBufferStream struct {
	mockBufferStream
	ownedCalls int
}

func (m *mockOwnedBufferStream) SendDatagramBufferOwned(buf []byte, offset, length int, owner quic.DatagramPayloadOwner) error {
	m.buffer = buf
	m.offset = offset
	m.length = length
	m.ownedCalls++
	return m.sendDatagramErr
}

type countingOwner struct{ releases atomic.Int32 }

func (o *countingOwner) Release() { o.releases.Add(1) }

func (m *mockBufferStream) SendDatagramBuffer(buf []byte, offset, length int) error {
	m.buffer = buf
	m.offset = offset
	m.length = length
	m.bufferCalls++
	return m.sendDatagramErr
}

func testIPv4Packet(t *testing.T) []byte {
	t.Helper()
	b, err := (&ipv4.Header{
		Version:  4,
		Len:      20,
		TTL:      64,
		Src:      net.IPv4(1, 2, 3, 4),
		Dst:      net.IPv4(5, 6, 7, 8),
		Protocol: 17,
	}).Marshal()
	require.NoError(t, err)
	return b
}

func TestWritePacketBufferUsesOptionalHeadroomSender(t *testing.T) {
	str := &mockBufferStream{}
	conn := newProxiedConn(str)
	ip := testIPv4Packet(t)
	buf := make([]byte, 9+len(ip))
	copy(buf[9:], ip)

	_, err := conn.WritePacketBuffer(buf, 9, len(ip))
	require.NoError(t, err)
	require.Equal(t, 1, str.bufferCalls)
	require.Equal(t, 8, str.offset)
	require.Equal(t, len(ip)+1, str.length)
	require.Equal(t, byte(0), buf[8])
	require.Equal(t, byte(63), buf[9+8])
	if &buf[8] != &str.buffer[str.offset] {
		t.Fatal("buffer-aware sender did not receive the original backing")
	}
	require.Equal(t, buf[8:8+str.length], str.buffer[str.offset:str.offset+str.length])
}

func TestWritePacketBufferKeepsLegacySenderCompatible(t *testing.T) {
	str := &mockStream{}
	conn := newProxiedConn(str)
	ip := testIPv4Packet(t)
	buf := make([]byte, 9+len(ip))
	copy(buf[9:], ip)

	_, err := conn.WritePacketBuffer(buf, 9, len(ip))
	require.NoError(t, err)
	require.Len(t, str.sentDatagrams, 1)
	require.Equal(t, byte(0), str.sentDatagrams[0][0])
	require.Equal(t, byte(63), str.sentDatagrams[0][9])
}

func TestWritePacketBufferRejectsInvalidRange(t *testing.T) {
	conn := newProxiedConn(&mockStream{})
	_, err := conn.WritePacketBuffer(make([]byte, 4), 5, 1)
	require.ErrorContains(t, err, "invalid packet buffer range")
}

func TestWritePacketBufferOwnedTransfersHeadroomOwner(t *testing.T) {
	str := &mockOwnedBufferStream{}
	conn := newProxiedConn(str)
	ip := testIPv4Packet(t)
	buf := make([]byte, 9+len(ip))
	copy(buf[9:], ip)
	owner := new(countingOwner)
	_, err := conn.WritePacketBufferOwned(buf, 9, len(ip), owner)
	require.NoError(t, err)
	require.Equal(t, 1, str.ownedCalls)
	require.Zero(t, owner.releases.Load(), "accepted owned send must retain ownership")
	require.Equal(t, byte(0), buf[8])
	owner.Release()
}

func TestWritePacketBufferOwnedReleasesOnSendError(t *testing.T) {
	str := &mockOwnedBufferStream{mockBufferStream: mockBufferStream{mockStream: mockStream{sendDatagramErr: &quic.DatagramTooLargeError{MaxDatagramPayloadSize: 1200}}}}
	conn := newProxiedConn(str)
	ip := testIPv4Packet(t)
	buf := make([]byte, 9+len(ip))
	copy(buf[9:], ip)
	owner := new(countingOwner)
	_, err := conn.WritePacketBufferOwned(buf, 9, len(ip), owner)
	require.NoError(t, err, "too-large errors are converted to ICMP")
	require.EqualValues(t, 1, owner.releases.Load())
}

func TestWritePacketBufferOwnedMapsTerminalErrorAndReleasesOwner(t *testing.T) {
	str := &mockOwnedBufferStream{mockBufferStream: mockBufferStream{mockStream: mockStream{sendDatagramErr: &quic.StreamError{Remote: true, ErrorCode: 42}}}}
	conn := newBareConn(str)
	ip := testIPv4Packet(t)
	buf := make([]byte, 9+len(ip))
	copy(buf[9:], ip)
	owner := new(countingOwner)

	_, err := conn.WritePacketBufferOwned(buf, 9, len(ip), owner)
	require.ErrorIs(t, err, net.ErrClosed)
	require.EqualValues(t, 1, owner.releases.Load())
}
