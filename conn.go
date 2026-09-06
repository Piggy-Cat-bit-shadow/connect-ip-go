package connectip

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/netip"
	"slices"
	"sync"

	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"

	"github.com/metacubex/quic-go"
	"github.com/metacubex/quic-go/http3"
	"github.com/metacubex/quic-go/quicvarint"
)

type CloseError struct {
	Remote bool
}

func (e *CloseError) Error() string        { return net.ErrClosed.Error() }
func (e *CloseError) Is(target error) bool { return target == net.ErrClosed }

const (
	ipProtoICMP   = 1
	ipProtoICMPv6 = 58
)

type http3Stream interface {
	io.ReadWriteCloser
	ReceiveDatagram(context.Context) ([]byte, error)
	SendDatagram([]byte) error
	CancelRead(quic.StreamErrorCode)
}

type http3BufferStream interface {
	ReceiveDatagramBuffer(context.Context) (*quic.DatagramBuffer, error)
}

type http3TryBufferStream interface {
	TryReceiveDatagramBuffer() (*quic.DatagramBuffer, error)
}

type http3BufferSender interface {
	SendDatagramBuffer([]byte, int, int) error
}

type http3OwnedBufferSender interface {
	SendDatagramBufferOwned([]byte, int, int, quic.DatagramPayloadOwner) error
}

// PacketPayloadOwner owns the backing storage passed to WritePacketBufferOwned.
type PacketPayloadOwner interface{ Release() }

// PacketBuffer is a zero-copy view over a QUIC datagram buffer.
type PacketBuffer quic.DatagramBuffer

func (b *PacketBuffer) Release() {
	if b != nil {
		(*quic.DatagramBuffer)(b).Release()
	}
}

var (
	_ http3Stream = &http3.Stream{}
	_ http3Stream = &http3.RequestStream{}
)

// If a packet is too large to fit into a QUIC datagram,
// we send an ICMP Packet Too Big packet.
// On IPv6, the minimum MTU of a link is 1280 bytes.
const minMTU = 1280

// Capsules normally don't remain queued: they are written to the CONNECT stream
// immediately. The queue only grows if the peer falls behind processing the stream.
const maxQueuedCapsules = 128

// Conn is a connection that proxies IP packets over HTTP/3.
type Conn struct {
	str         http3Stream
	closeConn   func() error
	writeNotify chan struct{}

	assignedAddressUpdates  chan []netip.Prefix
	availableRouteUpdates   chan []IPRoute
	dnsConfigurationUpdates chan []DNSConfiguration
	pref64Updates           chan []netip.Prefix

	mu sync.Mutex
	// queuedCapsules contains the capsules serialized by the send methods. This
	// allows callers to modify the values passed to a send method after it returns.
	queuedCapsules    [][]byte
	peerAddresses     []netip.Prefix // IP prefixes that we assigned to the peer
	localRoutes       []IPRoute      // IP routes that we advertised to the peer
	assignedAddresses []netip.Prefix

	closeChan chan struct{}
	closeErr  error
}

func newProxiedConn(str http3Stream, closeConn func() error) *Conn {
	c := &Conn{
		str:                     str,
		closeConn:               closeConn,
		writeNotify:             make(chan struct{}, 1),
		assignedAddressUpdates:  make(chan []netip.Prefix, 1),
		availableRouteUpdates:   make(chan []IPRoute, 1),
		dnsConfigurationUpdates: make(chan []DNSConfiguration, 1),
		pref64Updates:           make(chan []netip.Prefix, 1),
		closeChan:               make(chan struct{}),
	}
	go func() {
		if err := c.readFromStream(); err != nil {
			log.Printf("handling stream failed: %v", err)
			c.markClosedError(err, true)
		}
	}()
	go func() {
		if err := c.writeToStream(); err != nil {
			log.Printf("writing to stream failed: %v", err)
			c.markClosedError(err, true)
		}
	}()
	return c
}

// AdvertiseRoute schedules an advertisement of the available routes to the peer.
// It returns once the advertisement has been queued.
func (c *Conn) AdvertiseRoute(routes []IPRoute) error {
	for _, route := range routes {
		if route.StartIP.Compare(route.EndIP) == 1 {
			return fmt.Errorf("invalid route advertising start_ip: %s larger than %s", route.StartIP, route.EndIP)
		}
	}

	c.mu.Lock()
	if c.closeErr != nil {
		err := c.closeErr
		c.mu.Unlock()
		return err
	}
	routes = slices.Clone(routes)
	err := c.queueCapsule((&routeAdvertisementCapsule{IPAddressRanges: routes}).append(nil))
	if err == nil {
		c.localRoutes = routes
	}
	c.mu.Unlock()
	if err != nil {
		_ = c.Close()
		return err
	}
	return nil
}

// AssignAddresses schedules an assignment of address prefixes to the peer.
// It returns once the assignment has been queued.
func (c *Conn) AssignAddresses(prefixes []netip.Prefix) error {
	capsule := &addressAssignCapsule{AssignedAddresses: make([]AssignedAddress, 0, len(prefixes))}
	for _, p := range prefixes {
		capsule.AssignedAddresses = append(capsule.AssignedAddresses, AssignedAddress{IPPrefix: p})
	}

	c.mu.Lock()
	if c.closeErr != nil {
		err := c.closeErr
		c.mu.Unlock()
		return err
	}
	err := c.queueCapsule(capsule.append(nil))
	if err == nil {
		c.peerAddresses = slices.Clone(prefixes)
	}
	c.mu.Unlock()
	if err != nil {
		_ = c.Close()
		return err
	}
	return nil
}

// SendDNSConfiguration schedules a DNS configuration update to the peer.
// It returns once the update has been queued. The update supersedes the DNS
// configuration previously sent on this connection.
//
// To avoid leaking DNS traffic outside the tunnel, the application is responsible
// for advertising the corresponding routes before calling this method. See
// [Section 5 of draft-ietf-masque-connect-ip-dns-06].
//
// [Section 5 of draft-ietf-masque-connect-ip-dns-06]: https://datatracker.ietf.org/doc/html/draft-ietf-masque-connect-ip-dns-06#section-5
func (c *Conn) SendDNSConfiguration(configurations []DNSConfiguration) error {
	for _, config := range configurations {
		if err := config.validate(); err != nil {
			return fmt.Errorf("invalid DNS configuration: %w", err)
		}
	}
	return c.sendCapsule((&dnsAssignCapsule{DNSConfigurations: configurations}).append(nil))
}

// ReceiveDNSConfiguration waits for the next DNS configuration update from the peer.
// Each update supersedes the preceding one.
func (c *Conn) ReceiveDNSConfiguration(ctx context.Context) ([]DNSConfiguration, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-c.closeChan:
		return nil, c.closeErr
	case configurations := <-c.dnsConfigurationUpdates:
		return configurations, nil
	}
}

// SendPREF64Configuration schedules an update of the NAT64 prefixes to use for
// IPv6/IPv4 address synthesis. It returns once the update has been queued. An
// empty slice clears the previously sent configuration.
func (c *Conn) SendPREF64Configuration(prefixes []netip.Prefix) error {
	for i, prefix := range prefixes {
		if !prefix.IsValid() || !prefix.Addr().Is6() || prefix.Addr().Is4In6() {
			return fmt.Errorf("invalid NAT64 prefix %d: not an IPv6 prefix", i)
		}
		switch prefix.Bits() {
		case 32, 40, 48, 56, 64, 96:
		default:
			return fmt.Errorf("invalid NAT64 prefix %d: invalid prefix length %d", i, prefix.Bits())
		}
	}
	return c.sendCapsule((&pref64Capsule{Prefixes: prefixes}).append(nil))
}

// ReceivePREF64Configuration waits for the next NAT64 prefix update from the
// peer. An empty slice means that NAT64 prefixes are not available.
func (c *Conn) ReceivePREF64Configuration(ctx context.Context) ([]netip.Prefix, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-c.closeChan:
		return nil, c.closeErr
	case prefixes := <-c.pref64Updates:
		return prefixes, nil
	}
}

func (c *Conn) sendCapsule(capsuleData []byte) error {
	c.mu.Lock()
	if c.closeErr != nil {
		err := c.closeErr
		c.mu.Unlock()
		return err
	}
	err := c.queueCapsule(capsuleData)
	c.mu.Unlock()
	if err != nil {
		_ = c.Close()
		return err
	}
	return nil
}

func (c *Conn) queueCapsule(capsuleData []byte) error {
	if len(c.queuedCapsules) >= maxQueuedCapsules {
		return errors.New("connect-ip: capsule queue full")
	}
	// Consecutive capsules of the same type could be coalesced here, but that
	// micro-optimization is not worth the added complexity without evidence.
	c.queuedCapsules = append(c.queuedCapsules, capsuleData)

	select {
	case c.writeNotify <- struct{}{}:
	default:
	}
	return nil
}

func queueLatest[T any](ch chan T, value T) {
	for {
		select {
		case ch <- value:
			return
		case <-ch:
		}
	}
}

// LocalPrefixes returns the prefixes that the peer currently assigned.
// Note that at any point during the connection, the peer can change the assignment.
// It is therefore recommended to call this function in a loop.
func (c *Conn) LocalPrefixes(ctx context.Context) ([]netip.Prefix, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-c.closeChan:
		return nil, c.closeErr
	case prefixes := <-c.assignedAddressUpdates:
		// Callers are expected to treat returned prefixes as immutable.
		// Clone them defensively so accidental mutation cannot change connection state.
		return slices.Clone(prefixes), nil
	}
}

// Routes returns the routes that the peer currently advertised.
// Note that at any point during the connection, the peer can change the advertised routes.
// It is therefore recommended to call this function in a loop.
func (c *Conn) Routes(ctx context.Context) ([]IPRoute, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-c.closeChan:
		return nil, c.closeErr
	case routes := <-c.availableRouteUpdates:
		return routes, nil
	}
}

func (c *Conn) readFromStream() error {
	defer c.str.Close()
	p := http3.NewCapsuleParser(c.str)
	for {
		t, cr, err := p.Next()
		if err != nil {
			return err
		}
		switch t {
		case capsuleTypeAddressAssign:
			capsule, err := parseAddressAssignCapsule(cr)
			if err != nil {
				return err
			}
			prefixes := make([]netip.Prefix, 0, len(capsule.AssignedAddresses))
			for _, assigned := range capsule.AssignedAddresses {
				prefixes = append(prefixes, assigned.IPPrefix)
			}
			c.mu.Lock()
			c.assignedAddresses = prefixes
			c.mu.Unlock()
			queueLatest(c.assignedAddressUpdates, prefixes)
		case capsuleTypeAddressRequest:
			if _, err := parseAddressRequestCapsule(cr); err != nil {
				return err
			}
			return errors.New("connect-ip: address request not yet supported")
		case capsuleTypeRouteAdvertisement:
			capsule, err := parseRouteAdvertisementCapsule(cr)
			if err != nil {
				return err
			}
			queueLatest(c.availableRouteUpdates, capsule.IPAddressRanges)
		case capsuleTypeDNSAssign:
			capsule, err := parseDNSAssignCapsule(cr)
			if err != nil {
				return err
			}
			queueLatest(c.dnsConfigurationUpdates, capsule.DNSConfigurations)
		case capsuleTypePREF64:
			capsule, err := parsePREF64Capsule(cr)
			if err != nil {
				return err
			}
			queueLatest(c.pref64Updates, capsule.Prefixes)
		default:
			if err := cr.Discard(); err != nil {
				return err
			}
		}
	}
}

func (c *Conn) writeToStream() error {
	for {
		select {
		case <-c.closeChan:
			return c.closeErr
		case <-c.writeNotify:
			for {
				c.mu.Lock()
				if c.closeErr != nil {
					err := c.closeErr
					c.mu.Unlock()
					return err
				}
				if len(c.queuedCapsules) == 0 {
					c.mu.Unlock()
					break
				}
				capsuleData := c.queuedCapsules[0]
				c.queuedCapsules[0] = nil
				c.queuedCapsules = c.queuedCapsules[1:]
				c.mu.Unlock()

				if _, err := c.str.Write(capsuleData); err != nil {
					return err
				}
			}
		}
	}
}

func (c *Conn) ReadPacket(b []byte) (n int, err error) {
start:
	data, err := c.str.ReceiveDatagram(context.Background())
	if err != nil {
		return 0, c.mapPacketError(err)
	}
	contextID, n, err := quicvarint.Parse(data)
	if err != nil {
		// TODO: close connection
		return 0, fmt.Errorf("connect-ip: malformed datagram: %w", err)
	}
	if contextID != 0 {
		// Drop this datagram. We currently only support proxying of IP payloads.
		goto start
	}
	if err := c.handleIncomingProxiedPacket(data[n:]); err != nil {
		log.Printf("dropping proxied packet: %s", err)
		goto start
	}
	return copy(b, data[n:]), nil
}

// ReadPacketBuffer receives one validated IP packet without copying its
// backing buffer. The caller must release the returned buffer.
func (c *Conn) ReadPacketBuffer() (*PacketBuffer, error) {
	if s, ok := c.str.(http3BufferStream); ok {
		for {
			b, err := s.ReceiveDatagramBuffer(context.Background())
			if err != nil {
				return nil, c.mapPacketError(err)
			}
			contextID, n, err := quicvarint.Parse(b.Data)
			if err != nil {
				b.Release()
				return nil, fmt.Errorf("connect-ip: malformed datagram: %w", err)
			}
			if contextID != 0 || c.handleIncomingProxiedPacket(b.Data[n:]) != nil {
				b.Release()
				continue
			}
			b.Data = b.Data[n:]
			return (*PacketBuffer)(b), nil
		}
	}
	for {
		data, err := c.str.ReceiveDatagram(context.Background())
		if err != nil {
			return nil, c.mapPacketError(err)
		}
		contextID, n, err := quicvarint.Parse(data)
		if err != nil {
			return nil, fmt.Errorf("connect-ip: malformed datagram: %w", err)
		}
		if contextID != 0 || c.handleIncomingProxiedPacket(data[n:]) != nil {
			continue
		}
		return (*PacketBuffer)(&quic.DatagramBuffer{Data: data[n:]}), nil
	}
}

// TryReadPacketBuffer drains one already queued datagram without waiting.
func (c *Conn) TryReadPacketBuffer() (*PacketBuffer, error) {
	s, ok := c.str.(http3TryBufferStream)
	if !ok {
		return nil, context.Canceled
	}
	for {
		b, err := s.TryReceiveDatagramBuffer()
		if err != nil {
			return nil, c.mapPacketError(err)
		}
		contextID, n, err := quicvarint.Parse(b.Data)
		if err != nil {
			b.Release()
			return nil, fmt.Errorf("connect-ip: malformed datagram: %w", err)
		}
		if contextID != 0 || c.handleIncomingProxiedPacket(b.Data[n:]) != nil {
			b.Release()
			continue
		}
		b.Data = b.Data[n:]
		return (*PacketBuffer)(b), nil
	}
}

func (c *Conn) mapPacketError(err error) error {
	if normalized, terminal := normalizeTerminalError(err); terminal {
		return c.markClosedError(normalized, true)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closeErr != nil {
		return c.closeErr
	}
	return err
}

// normalizeTerminalError maps transport-level shutdowns to the stable error
// contract exposed by CONNECT-IP. It intentionally leaves context and other
// non-terminal errors untouched.
func normalizeTerminalError(err error) (error, bool) {
	if err == nil {
		return nil, false
	}
	var (
		closeErr     *CloseError
		appErr       *quic.ApplicationError
		transportErr *quic.TransportError
		streamErr    *quic.StreamError
		resetErr     *quic.StatelessResetError
		idleErr      *quic.IdleTimeoutError
		handshakeErr *quic.HandshakeTimeoutError
		h3Err        *http3.Error
	)
	switch {
	case errors.As(err, &closeErr):
		return closeErr, true
	case errors.As(err, &appErr):
		return &CloseError{Remote: appErr.Remote}, true
	case errors.As(err, &transportErr):
		return &CloseError{Remote: transportErr.Remote}, true
	case errors.As(err, &streamErr):
		return &CloseError{Remote: streamErr.Remote}, true
	case errors.As(err, &resetErr), errors.As(err, &idleErr), errors.As(err, &handshakeErr):
		return &CloseError{Remote: true}, true
	case errors.As(err, &h3Err):
		return &CloseError{Remote: h3Err.Remote}, true
	case errors.Is(err, net.ErrClosed), errors.Is(err, io.EOF):
		return &CloseError{Remote: true}, true
	default:
		return err, false
	}
}

// markClosedError records the first terminal state and wakes all blocked
// operations. The caller may safely race with Close and other transport
// failures; the first state remains authoritative.
func (c *Conn) markClosedError(err error, remote bool) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closeErr == nil {
		if normalized, terminal := normalizeTerminalError(err); terminal {
			c.closeErr = normalized
		} else if err != nil {
			c.closeErr = err
		} else {
			c.closeErr = &CloseError{Remote: remote}
		}
		close(c.closeChan)
	}
	return c.closeErr
}

func (c *Conn) handleIncomingProxiedPacket(data []byte) error {
	if len(data) == 0 {
		return errors.New("connect-ip: empty packet")
	}
	var src, dst netip.Addr
	var ipProto uint8
	switch v := ipVersion(data); v {
	default:
		return fmt.Errorf("connect-ip: unknown IP versions: %d", v)
	case 4:
		if len(data) < ipv4.HeaderLen {
			return fmt.Errorf("connect-ip: malformed datagram: too short")
		}
		src = netip.AddrFrom4([4]byte(data[12:16]))
		dst = netip.AddrFrom4([4]byte(data[16:20]))
		ipProto = data[9]
	case 6:
		if len(data) < ipv6.HeaderLen {
			return fmt.Errorf("connect-ip: malformed datagram: too short")
		}
		src = netip.AddrFrom16([16]byte(data[8:24]))
		dst = netip.AddrFrom16([16]byte(data[24:40]))
		ipProto = data[6]
	}

	c.mu.Lock()
	assignedAddresses := c.assignedAddresses
	localRoutes := c.localRoutes
	peerAddresses := c.peerAddresses
	c.mu.Unlock()

	// We don't necessarily assign any addresses to the peer.
	// For example, in the Remote Access VPN use case (RFC 9484, section 8.1),
	// the client accepts incoming traffic from all IPs.
	if peerAddresses != nil {
		if !slices.ContainsFunc(peerAddresses, func(p netip.Prefix) bool { return p.Contains(src) }) {
			// TODO: send ICMP
			return fmt.Errorf("connect-ip: datagram source address not allowed: %s", src)
		}
	}

	// The destination IP address is valid if it
	// 1. is within one of the ranges assigned to us, or
	// 2. is within one of the ranges that we advertised to the peer.
	var isAllowedDst bool
	if len(assignedAddresses) > 0 {
		isAllowedDst = slices.ContainsFunc(assignedAddresses, func(p netip.Prefix) bool { return p.Contains(dst) })
	}
	if !isAllowedDst {
		isAllowedDst = slices.ContainsFunc(localRoutes, func(r IPRoute) bool {
			if r.StartIP.Compare(dst) > 0 || dst.Compare(r.EndIP) > 0 {
				return false
			}
			// ICMP is always allowed
			if (ipVersion(data) == 4 && ipProto == ipProtoICMP) || (ipVersion(data) == 6 && ipProto == ipProtoICMPv6) {
				return true
			}
			// TODO: walk the chain of IPv6 extensions
			// See section 4.8 of RFC 9484 for details.
			return r.IPProtocol == 0 || r.IPProtocol == ipProto
		})
	}
	if !isAllowedDst {
		// TODO: send ICMP
		return fmt.Errorf("connect-ip: datagram destination address / protocol not allowed: %s (protocol: %d)", dst, ipProto)
	}
	return nil
}

// WritePacket writes an IP packet to the stream.
// If sending the packet fails, it might return an ICMP packet.
// It is the caller's responsibility to send the ICMP packet to the sender.
func (c *Conn) WritePacket(b []byte) (icmp []byte, err error) {
	data, err := c.composeDatagram(b)
	if err != nil {
		log.Printf("dropping proxied packet (%d bytes) that can't be proxied: %s", len(b), err)
		return nil, nil
	}
	if err := c.str.SendDatagram(data); err != nil {
		if _, ok := errors.AsType[*quic.DatagramTooLargeError](err); ok {
			icmpPacket, err := composeICMPTooLargePacket(b, minMTU)
			if err != nil {
				log.Printf("failed to compose ICMP too large packet: %s", err)
			}
			return icmpPacket, nil
		}
		select {
		case <-c.closeChan:
			return nil, c.closeErr
		default:
			return nil, c.mapPacketError(err)
		}
	}
	return nil, nil
}

// WritePacketBuffer sends an IP packet from a caller-provided buffer with
// room for the CONNECT-IP context ID immediately before offset.
func (c *Conn) WritePacketBuffer(buf []byte, offset, length int) ([]byte, error) {
	if offset < len(contextIDZero) || offset > len(buf) || length < 0 || length > len(buf)-offset {
		return nil, fmt.Errorf("connect-ip: invalid packet buffer range: offset=%d length=%d buffer=%d", offset, length, len(buf))
	}
	p := buf[offset : offset+length]
	if err := c.composeDatagramInPlace(p); err != nil {
		return nil, nil
	}
	copy(buf[offset-len(contextIDZero):offset], contextIDZero)
	dataOffset := offset - len(contextIDZero)
	dataLength := length + len(contextIDZero)
	if sender, ok := c.str.(http3BufferSender); ok {
		err := sender.SendDatagramBuffer(buf, dataOffset, dataLength)
		if err != nil {
			return nil, c.mapPacketError(err)
		}
		return nil, nil
	}
	if err := c.str.SendDatagram(buf[dataOffset : dataOffset+dataLength]); err != nil {
		if _, ok := errors.AsType[*quic.DatagramTooLargeError](err); ok {
			return composeICMPTooLargePacket(p, minMTU)
		}
		return nil, c.mapPacketError(err)
	}
	return nil, nil
}

// WritePacketBufferOwned transfers ownership only when the lower layer
// accepts the owned send. All rejected or synchronous fallback paths release it.
func (c *Conn) WritePacketBufferOwned(buf []byte, offset, length int, owner PacketPayloadOwner) (icmp []byte, err error) {
	transferred := false
	defer func() {
		if !transferred && owner != nil {
			owner.Release()
		}
	}()
	if offset < len(contextIDZero) || offset > len(buf) || length < 0 || length > len(buf)-offset {
		return nil, fmt.Errorf("connect-ip: invalid packet buffer range: offset=%d length=%d buffer=%d", offset, length, len(buf))
	}
	p := buf[offset : offset+length]
	if err := c.composeDatagramInPlace(p); err != nil {
		return nil, nil
	}
	copy(buf[offset-len(contextIDZero):offset], contextIDZero)
	dataOffset := offset - len(contextIDZero)
	dataLength := length + len(contextIDZero)
	if sender, ok := c.str.(http3OwnedBufferSender); ok {
		err = sender.SendDatagramBufferOwned(buf, dataOffset, dataLength, owner)
		if err == nil {
			transferred = true
		}
	} else if sender, ok := c.str.(http3BufferSender); ok {
		err = sender.SendDatagramBuffer(buf, dataOffset, dataLength)
	} else {
		err = c.str.SendDatagram(buf[dataOffset : dataOffset+dataLength])
	}
	if err != nil {
		if _, ok := errors.AsType[*quic.DatagramTooLargeError](err); ok {
			return composeICMPTooLargePacket(p, minMTU)
		}
		return nil, c.mapPacketError(err)
	}
	return nil, nil
}

func (c *Conn) composeDatagram(b []byte) ([]byte, error) {
	if err := c.composeDatagramInPlace(b); err != nil {
		return nil, err
	}
	data := make([]byte, 0, len(contextIDZero)+len(b))
	data = append(data, contextIDZero...)
	data = append(data, b...)
	return data, nil
}

func (c *Conn) composeDatagramInPlace(b []byte) error {
	if len(b) == 0 {
		return nil
	}
	switch v := ipVersion(b); v {
	case 4:
		if len(b) < ipv4.HeaderLen {
			return fmt.Errorf("connect-ip: IPv4 packet too short")
		}
		ihlWords := b[0] & 0x0f
		if ihlWords < 5 {
			return fmt.Errorf("connect-ip: invalid IPv4 header length: %d", ihlWords)
		}
		ihl := int(ihlWords) * 4
		if ihl > len(b) {
			return fmt.Errorf("connect-ip: IPv4 header length %d exceeds packet length %d", ihl, len(b))
		}
		if b[8] <= 1 {
			return fmt.Errorf("connect-ip: datagram TTL too small: %d", b[8])
		}
		b[8]--
		binary.BigEndian.PutUint16(b[10:12], calculateIPv4ChecksumBytes(b[:ihl]))
	case 6:
		if len(b) < ipv6.HeaderLen {
			return fmt.Errorf("connect-ip: IPv6 packet too short")
		}
		if b[7] <= 1 {
			return fmt.Errorf("connect-ip: datagram Hop Limit too small: %d", b[7])
		}
		b[7]--
	default:
		return fmt.Errorf("connect-ip: unknown IP versions: %d", v)
	}
	return nil
}

func (c *Conn) Close() error {
	c.markClosedError(&CloseError{Remote: false}, false)
	c.mu.Lock()
	closeConn := c.closeConn
	c.closeConn = nil
	c.mu.Unlock()
	c.str.CancelRead(quic.StreamErrorCode(http3.ErrCodeNoError))
	err := c.str.Close()
	if closeConn != nil {
		return errors.Join(err, closeConn())
	}
	return err
}

func ipVersion(b []byte) uint8 { return b[0] >> 4 }
