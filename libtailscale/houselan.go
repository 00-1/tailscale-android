// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package libtailscale

// House build: home-LAN UDP straight over the home Wi-Fi.
//
// At home the phone's internet stays on LTE (the house Wi-Fi is LAN only), and the Flint shares the
// house LAN (192.168.8.0/24) over Tailscale, so the VPN routes that subnet into the tun. Unicast TCP/UDP
// to house devices then reaches them through the Flint, but discovery broadcasts (e.g. WiZ bulbs on
// UDP 38899 to 192.168.8.255, the "is anyone there?" step most gadget apps use) die in the tunnel.
//
// While the phone is on the home Wi-Fi, IPv4 UDP that apps send into the tun for 192.168.8.0/24
// (broadcast and unicast) is taken out of the tunnel here and sent from a UDP socket bound to the home
// Wi-Fi (one per app source address and port, SO_BROADCAST on); replies are written back into the tun
// as if they came straight from the device. TCP, ICMP, fragments and everything else take the normal
// path. Away from home nothing is diverted, so behaviour is exactly upstream.

import (
	"context"
	"encoding/binary"
	"log"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/tailscale/wireguard-go/tun"
)

var (
	houseLANPrefix = netip.MustParsePrefix("192.168.8.0/24")
	houseLANIdle   = 2 * time.Minute
)

type houseLANFlow struct {
	conn *net.UDPConn
	app  netip.AddrPort // the app's source address in the tun
	last atomic.Int64   // unix nanos of the last packet either way
}

type houseLAN struct {
	home atomic.Bool // the phone is on the home Wi-Fi (checked with a test bind)

	mu    sync.Mutex
	bind  func(fd int) bool      // binds a socket to the home Wi-Fi; false when not at home
	write func(pkt []byte) error // writes an IP packet into the tun, towards the apps
	flows map[netip.AddrPort]*houseLANFlow

	out   chan []byte // diverted packets, handled off the tun read path
	ipID  atomic.Uint32
	start sync.Once
}

var houseLANFwd = &houseLAN{flows: map[netip.AddrPort]*houseLANFlow{}, out: make(chan []byte, 256)}

// setup wires the forwarder to the app (socket binding) and to the tun (writing replies).
func (h *houseLAN) setup(bind func(fd int) bool, write func(pkt []byte) error) {
	h.mu.Lock()
	h.bind, h.write = bind, write
	h.mu.Unlock()
	h.start.Do(func() { go h.run() })
	h.recheck("start")
}

// recheck works out whether the phone is on the home Wi-Fi (by test-binding a UDP socket to it)
// and drops all flows when that changes.
func (h *houseLAN) recheck(why string) {
	h.mu.Lock()
	bind := h.bind
	h.mu.Unlock()
	home := false
	if bind != nil {
		if fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_DGRAM, 0); err == nil {
			home = bind(fd)
			syscall.Close(fd)
		}
	}
	if h.home.Swap(home) != home {
		log.Printf("house: home LAN UDP over Wi-Fi %v (%s)", map[bool]string{true: "on", false: "off"}[home], why)
	}
	h.closeAll()
}

func (h *houseLAN) closeAll() {
	h.mu.Lock()
	defer h.mu.Unlock()
	for k, f := range h.flows {
		f.conn.Close()
		delete(h.flows, k)
	}
}

// filter removes the packets it diverts from a tun read and returns how many remain. It must be cheap:
// it runs on the tun read path for every packet the phone sends.
func (h *houseLAN) filter(slab []byte, packets []tun.ReadPacket, n int) int {
	if !h.home.Load() {
		return n
	}
	kept := 0
	for i := 0; i < n; i++ {
		p := packets[i]
		pkt := slab[p.Offset : p.Offset+p.Size]
		if h.divertable(pkt) {
			cp := make([]byte, len(pkt))
			copy(cp, pkt)
			select {
			case h.out <- cp:
			default: // full: drop, as a congested network would
			}
			continue
		}
		packets[kept] = p
		kept++
	}
	return kept
}

// divertable reports whether pkt is an unfragmented IPv4 UDP packet to the home LAN.
func (h *houseLAN) divertable(pkt []byte) bool {
	if len(pkt) < 28 || pkt[0]>>4 != 4 || pkt[9] != syscall.IPPROTO_UDP {
		return false
	}
	ihl := int(pkt[0]&0x0f) * 4
	if ihl < 20 || len(pkt) < ihl+8 {
		return false
	}
	if binary.BigEndian.Uint16(pkt[6:8])&0x3fff != 0 { // MF flag or a fragment offset
		return false
	}
	dst := netip.AddrFrom4([4]byte(pkt[16:20]))
	return houseLANPrefix.Contains(dst)
}

func (h *houseLAN) run() {
	tick := time.NewTicker(30 * time.Second)
	defer tick.Stop()
	for {
		select {
		case pkt := <-h.out:
			h.send(pkt)
		case <-tick.C:
			h.reap()
		}
	}
}

func (h *houseLAN) reap() {
	cutoff := time.Now().Add(-houseLANIdle).UnixNano()
	h.mu.Lock()
	defer h.mu.Unlock()
	for k, f := range h.flows {
		if f.last.Load() < cutoff {
			f.conn.Close()
			delete(h.flows, k)
		}
	}
}

func (h *houseLAN) send(pkt []byte) {
	ihl := int(pkt[0]&0x0f) * 4
	src := netip.AddrPortFrom(netip.AddrFrom4([4]byte(pkt[12:16])), binary.BigEndian.Uint16(pkt[ihl:]))
	dst := netip.AddrPortFrom(netip.AddrFrom4([4]byte(pkt[16:20])), binary.BigEndian.Uint16(pkt[ihl+2:]))
	ulen := int(binary.BigEndian.Uint16(pkt[ihl+4:]))
	if ulen < 8 || ihl+ulen > len(pkt) {
		return
	}
	f := h.flow(src)
	if f == nil {
		return
	}
	f.last.Store(time.Now().UnixNano())
	if _, err := f.conn.WriteToUDPAddrPort(pkt[ihl+8:ihl+ulen], dst); err != nil {
		log.Printf("house: home LAN UDP %v -> %v: %v", src, dst, err)
	}
}

// flow returns the Wi-Fi socket for an app's source address, opening it if needed.
func (h *houseLAN) flow(app netip.AddrPort) *houseLANFlow {
	h.mu.Lock()
	f, ok := h.flows[app]
	bind := h.bind
	h.mu.Unlock()
	if ok {
		return f
	}
	if bind == nil {
		return nil
	}
	bound := false
	lc := net.ListenConfig{Control: func(network, address string, c syscall.RawConn) error {
		return c.Control(func(fd uintptr) {
			syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_BROADCAST, 1)
			bound = bind(int(fd))
		})
	}}
	pc, err := lc.ListenPacket(context.Background(), "udp4", "0.0.0.0:0")
	if err != nil {
		log.Printf("house: home LAN UDP socket for %v: %v", app, err)
		return nil
	}
	if !bound { // left the home Wi-Fi meanwhile
		pc.Close()
		h.home.Store(false)
		return nil
	}
	f = &houseLANFlow{conn: pc.(*net.UDPConn), app: app}
	f.last.Store(time.Now().UnixNano())
	h.mu.Lock()
	if old, ok := h.flows[app]; ok { // lost a race: keep the first
		h.mu.Unlock()
		pc.Close()
		return old
	}
	h.flows[app] = f
	h.mu.Unlock()
	go h.replies(f)
	return f
}

// replies writes what comes back to a flow's socket into the tun, addressed to the app.
func (h *houseLAN) replies(f *houseLANFlow) {
	buf := make([]byte, 65535)
	for {
		n, from, err := f.conn.ReadFromUDPAddrPort(buf)
		if err != nil {
			return // closed (idle, left home, or rebind)
		}
		from = netip.AddrPortFrom(from.Addr().Unmap(), from.Port())
		if !from.Addr().Is4() {
			continue
		}
		f.last.Store(time.Now().UnixNano())
		h.mu.Lock()
		write := h.write
		h.mu.Unlock()
		if write == nil {
			continue
		}
		if err := write(h.packet(from, f.app, buf[:n])); err != nil {
			log.Printf("house: home LAN UDP reply %v -> %v: %v", from, f.app, err)
		}
	}
}

// packetHeadroom is spare room before each packet written to the tun, in case the device wants a
// virtio-net header in front (it doesn't on Android, but it costs nothing).
const packetHeadroom = 16

// packet builds an IPv4/UDP packet from src to dst carrying payload, preceded by packetHeadroom bytes.
func (h *houseLAN) packet(src, dst netip.AddrPort, payload []byte) []byte {
	b := make([]byte, packetHeadroom+28+len(payload))
	ip := b[packetHeadroom:]
	ip[0] = 0x45
	binary.BigEndian.PutUint16(ip[2:], uint16(28+len(payload)))
	binary.BigEndian.PutUint16(ip[4:], uint16(h.ipID.Add(1)))
	ip[8] = 64
	ip[9] = syscall.IPPROTO_UDP
	s4, d4 := src.Addr().As4(), dst.Addr().As4()
	copy(ip[12:16], s4[:])
	copy(ip[16:20], d4[:])
	binary.BigEndian.PutUint16(ip[10:], checksum(ip[:20], 0))
	u := ip[20:]
	binary.BigEndian.PutUint16(u[0:], src.Port())
	binary.BigEndian.PutUint16(u[2:], dst.Port())
	binary.BigEndian.PutUint16(u[4:], uint16(8+len(payload)))
	copy(u[8:], payload)
	// UDP checksum over the pseudo-header (src, dst, proto, length) and the datagram.
	var pseudo uint32
	pseudo += uint32(binary.BigEndian.Uint16(s4[0:])) + uint32(binary.BigEndian.Uint16(s4[2:]))
	pseudo += uint32(binary.BigEndian.Uint16(d4[0:])) + uint32(binary.BigEndian.Uint16(d4[2:]))
	pseudo += syscall.IPPROTO_UDP + uint32(len(u))
	cs := checksum(u, pseudo)
	if cs == 0 {
		cs = 0xffff
	}
	binary.BigEndian.PutUint16(u[6:], cs)
	return b
}

// checksum is the Internet checksum of b, starting from the partial sum initial.
func checksum(b []byte, initial uint32) uint16 {
	sum := initial
	for len(b) >= 2 {
		sum += uint32(binary.BigEndian.Uint16(b))
		b = b[2:]
	}
	if len(b) == 1 {
		sum += uint32(b[0]) << 8
	}
	for sum>>16 != 0 {
		sum = sum&0xffff + sum>>16
	}
	return ^uint16(sum)
}
