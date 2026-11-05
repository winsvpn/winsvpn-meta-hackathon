// Package peer is a test fixture: the node end of the carrying canary. It is
// a real userspace AmneziaWG responder (the same amneziawg-go v3 module and
// version as the client and as the data-plane nodes) on an in-process network
// stack, with a tiny DNS responder listening inside the tunnel at the node's
// inner router address. It is used by the Go tests and by the
// awg-carry-testpeer command the Python suites run; it is never shipped.
package peer

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"

	"github.com/amnezia-vpn/amneziawg-go/v3/conn"
	"github.com/amnezia-vpn/amneziawg-go/v3/device"
	"github.com/amnezia-vpn/amneziawg-go/v3/tun/netstack"
	"golang.org/x/crypto/curve25519"
)

// Keypair is one throwaway X25519 key pair in the base64 form the hub stores.
type Keypair struct {
	Private string
	Public  string
}

// NewKeypair draws a fresh key pair from the system entropy source.
func NewKeypair() (Keypair, error) {
	private := make([]byte, 32)
	if _, err := rand.Read(private); err != nil {
		return Keypair{}, err
	}
	private[0] &= 248
	private[31] &= 127
	private[31] |= 64
	public, err := curve25519.X25519(private, curve25519.Basepoint)
	if err != nil {
		return Keypair{}, err
	}
	return Keypair{
		Private: base64.StdEncoding.EncodeToString(private),
		Public:  base64.StdEncoding.EncodeToString(public),
	}, nil
}

// Config describes the responder.
type Config struct {
	// Private key of the node, base64.
	PrivateKey string
	// Public key of the canary client, base64; the only peer admitted.
	ClientPublicKey string
	// Allowed inner address of that peer, usually 10.8.255.1.
	ClientAddress netip.Addr
	// The node's inner router address, where the DNS responder listens.
	InnerAddress netip.Addr
	DNSPort      uint16
	// UAPI lines of the obfuscation profile (jc=, jmin=, ...), as the
	// client renders them.
	Profile []string
	// Answer this name with this address; any other question gets NXDOMAIN
	// so a reply is never a reflex.
	Name    string
	Address netip.Addr
	// ListenPort 0 picks a free port.
	ListenPort uint16
	// Silent keeps the DNS responder from ever answering (handshake still
	// completes).
	Silent bool
}

// Peer is a running responder.
type Peer struct {
	Port    uint16
	dev     *device.Device
	conn    interface{ Close() error }
	once    sync.Once
	queries int
	mu      sync.Mutex
}

// Start brings the responder up on a loopback UDP port.
func Start(cfg Config) (*Peer, error) {
	privateHex, err := keyHex(cfg.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("private key: %w", err)
	}
	clientHex, err := keyHex(cfg.ClientPublicKey)
	if err != nil {
		return nil, fmt.Errorf("client public key: %w", err)
	}
	tunDevice, inner, err := netstack.CreateNetTUN([]netip.Addr{cfg.InnerAddress}, nil, 1280)
	if err != nil {
		return nil, err
	}
	dev := device.NewDevice(tunDevice, conn.NewStdNetBind(), device.NewLogger(device.LogLevelSilent, ""))
	var uapi strings.Builder
	fmt.Fprintf(&uapi, "private_key=%s\n", privateHex)
	fmt.Fprintf(&uapi, "listen_port=%d\n", cfg.ListenPort)
	for _, line := range cfg.Profile {
		uapi.WriteString(line)
		uapi.WriteByte('\n')
	}
	fmt.Fprintf(&uapi, "public_key=%s\n", clientHex)
	fmt.Fprintf(&uapi, "allowed_ip=%s/32\n", cfg.ClientAddress.String())
	if err := dev.IpcSet(uapi.String()); err != nil {
		dev.Close()
		return nil, fmt.Errorf("configure responder: %w", err)
	}
	if err := dev.Up(); err != nil {
		dev.Close()
		return nil, fmt.Errorf("responder up: %w", err)
	}
	port, err := listenPort(dev)
	if err != nil {
		dev.Close()
		return nil, err
	}
	socket, err := inner.ListenUDPAddrPort(netip.AddrPortFrom(cfg.InnerAddress, cfg.DNSPort))
	if err != nil {
		dev.Close()
		return nil, fmt.Errorf("inner DNS socket: %w", err)
	}
	p := &Peer{Port: port, dev: dev, conn: socket}
	go p.answer(socket, cfg)
	return p, nil
}

// Queries is how many DNS questions arrived through the tunnel.
func (p *Peer) Queries() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.queries
}

// Handshook reports whether any handshake completed.
func (p *Peer) Handshook() bool {
	document, err := p.dev.IpcGet()
	if err != nil {
		return false
	}
	for _, line := range strings.Split(document, "\n") {
		key, value, found := strings.Cut(line, "=")
		if found && key == "last_handshake_time_sec" && value != "" && value != "0" {
			return true
		}
	}
	return false
}

// Close tears the responder down.
func (p *Peer) Close() {
	p.once.Do(func() {
		p.conn.Close()
		p.dev.Close()
	})
}

// udpConn is the inner socket: a gonet.UDPConn in practice.
type udpConn interface {
	ReadFrom([]byte) (int, net.Addr, error)
	WriteTo([]byte, net.Addr) (int, error)
	Close() error
}

func (p *Peer) answer(socket udpConn, cfg Config) {
	buffer := make([]byte, 4096)
	for {
		n, from, err := socket.ReadFrom(buffer)
		if err != nil {
			return
		}
		p.mu.Lock()
		p.queries++
		p.mu.Unlock()
		if cfg.Silent {
			continue
		}
		response := Answer(buffer[:n], cfg.Name, cfg.Address)
		if response == nil {
			continue
		}
		if _, err := socket.WriteTo(response, from); err != nil {
			return
		}
	}
}

// Answer builds the DNS response the node's resolver would give: an A record
// for the hub name, NXDOMAIN for any other name, nil for a malformed query.
func Answer(query []byte, name string, address netip.Addr) []byte {
	if len(query) < 17 || query[2]&0x80 != 0 || binary.BigEndian.Uint16(query[4:6]) != 1 {
		return nil
	}
	end := 12
	var labels []string
	for end < len(query) {
		length := int(query[end])
		if length == 0 {
			end++
			break
		}
		if length&0xC0 != 0 || end+1+length > len(query) {
			return nil
		}
		labels = append(labels, string(query[end+1:end+1+length]))
		end += 1 + length
	}
	if end+4 > len(query) {
		return nil
	}
	question := query[12 : end+4]
	qtype := binary.BigEndian.Uint16(query[end : end+2])
	asked := strings.ToLower(strings.Join(labels, "."))
	wanted := strings.ToLower(strings.TrimSuffix(name, "."))
	header := make([]byte, 12)
	copy(header[:2], query[:2])
	binary.BigEndian.PutUint16(header[4:6], 1)
	if asked != wanted || qtype != 1 || !address.Is4() {
		binary.BigEndian.PutUint16(header[2:4], 0x8183)
		return append(header, question...)
	}
	binary.BigEndian.PutUint16(header[2:4], 0x8180)
	binary.BigEndian.PutUint16(header[6:8], 1)
	record := []byte{0xC0, 0x0C, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4}
	ip := address.As4()
	record = append(record, ip[:]...)
	return append(append(header, question...), record...)
}

func keyHex(value string) (string, error) {
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(value))
	if err != nil {
		return "", err
	}
	if len(raw) != 32 {
		return "", errors.New("not a 32-byte key")
	}
	return hex.EncodeToString(raw), nil
}

func listenPort(dev *device.Device) (uint16, error) {
	document, err := dev.IpcGet()
	if err != nil {
		return 0, err
	}
	for _, line := range strings.Split(document, "\n") {
		key, value, found := strings.Cut(line, "=")
		if found && key == "listen_port" {
			port, err := strconv.ParseUint(value, 10, 16)
			if err != nil || port == 0 {
				return 0, errors.New("responder has no listen port")
			}
			return uint16(port), nil
		}
	}
	return 0, errors.New("responder reported no listen port")
}
