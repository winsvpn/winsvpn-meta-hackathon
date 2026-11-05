package carrier

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"golang.org/x/net/ipv4"
)

type RelayConfig struct {
	MaxDatagram       int
	IdleTimeout       time.Duration
	ExpectedLocalPeer *net.UDPAddr
	BatchSize         int
	SocketBufferBytes int
}

// RelayLocalUDP joins a single local AWG socket to an authenticated carrier.
// Production callers should set ExpectedLocalPeer to the candidate-isolated AWG
// socket. Legacy callers without it pin the first local sender for the relay
// lifetime. Packets from every other local process are rejected.
func RelayLocalUDP(ctx context.Context, local *net.UDPConn, remote net.PacketConn, config RelayConfig) error {
	return relayLocalUDP(
		ctx,
		local,
		remote,
		config,
		newRelayBatchConn,
		newRelayBatchConn,
	)
}

func relayLocalUDP(
	ctx context.Context,
	local *net.UDPConn,
	remote net.PacketConn,
	config RelayConfig,
	localBatchFactory relayBatchFactory,
	remoteBatchFactory relayBatchFactory,
) error {
	if ctx == nil || local == nil || remote == nil {
		return errors.New("relay context and packet connections are required")
	}
	maxDatagram := config.MaxDatagram
	if maxDatagram <= 0 {
		maxDatagram = DefaultMaxDatagram
	}
	if maxDatagram > AbsoluteMaxDatagram {
		return errors.New("relay datagram limit exceeds 1500 bytes")
	}
	if config.ExpectedLocalPeer != nil &&
		(config.ExpectedLocalPeer.IP == nil ||
			config.ExpectedLocalPeer.Port < 1 ||
			config.ExpectedLocalPeer.Port > 65535) {
		return errors.New("expected local AWG peer is invalid")
	}
	batchSize := config.BatchSize
	if batchSize <= 0 {
		batchSize = DefaultRelayBatchSize
	}
	if batchSize > MaxRelayBatchSize {
		return fmt.Errorf("relay batch size exceeds %d packets", MaxRelayBatchSize)
	}
	if localBatchFactory == nil || remoteBatchFactory == nil {
		return errors.New("relay batch factories are required")
	}
	if err := configureRelaySocketBuffers(
		local,
		remote,
		config.SocketBufferBytes,
	); err != nil {
		return err
	}
	localPackets := newRelayPacketIO(
		local,
		config.ExpectedLocalPeer,
		localBatchFactory,
	)
	remotePackets := newRelayPacketIO(remote, nil, remoteBatchFactory)
	var peerMu sync.RWMutex
	peer := cloneUDPAddr(config.ExpectedLocalPeer)
	results := make(chan error, 3)
	shutdown := make(chan struct{})
	var shutdownOnce sync.Once
	stopWorkers := func() {
		shutdownOnce.Do(func() { close(shutdown) })
	}
	var workers sync.WaitGroup
	workers.Add(3)
	go func() {
		defer workers.Done()
		messages := make([]ipv4.Message, batchSize)
		for index := range messages {
			messages[index].Buffers = [][]byte{
				make([]byte, maxDatagram+1),
			}
		}
		outbound := make([]ipv4.Message, batchSize)
		outboundBuffers := make([][]byte, batchSize)
		for index := range outbound {
			outbound[index].Buffers = outboundBuffers[index : index+1]
		}
		accepted := make([]bool, batchSize)
		for {
			if config.IdleTimeout > 0 {
				_ = local.SetReadDeadline(time.Now().Add(config.IdleTimeout))
			}
			count, readErr := localPackets.readBatch(messages)
			if count == 0 && readErr != nil {
				results <- readErr
				return
			}
			if count < 1 || count > len(messages) {
				if readErr != nil {
					results <- readErr
					return
				}
				results <- errors.New("local UDP batch read returned an invalid count")
				return
			}
			clear(accepted[:count])
			peerMu.Lock()
			for index := range count {
				message := &messages[index]
				if message.N < 0 || message.N > len(message.Buffers[0]) {
					peerMu.Unlock()
					results <- errors.New(
						"local UDP batch read returned an invalid packet size",
					)
					return
				}
				sender, ok := message.Addr.(*net.UDPAddr)
				if !ok || sender == nil {
					peerMu.Unlock()
					results <- errors.New("local UDP batch sender is not UDP")
					return
				}
				if peer == nil {
					peer = cloneUDPAddr(sender)
				}
				if message.N <= maxDatagram && sameUDPAddr(peer, sender) {
					accepted[index] = true
				}
			}
			peerMu.Unlock()
			outboundCount := 0
			for index := range count {
				message := &messages[index]
				if accepted[index] {
					outboundBuffers[outboundCount] =
						message.Buffers[0][:message.N]
					outboundCount++
				}
			}
			if err := writeAllRelayMessages(
				remotePackets,
				outbound[:outboundCount],
			); err != nil {
				results <- fmt.Errorf(
					"local-to-carrier relay: %w",
					err,
				)
				return
			}
			clear(outboundBuffers[:outboundCount])
			for index := range count {
				message := &messages[index]
				if message.N > 0 {
					clear(message.Buffers[0][:message.N])
				}
				message.N = 0
				message.NN = 0
				message.Flags = 0
				message.Addr = nil
			}
			if readErr != nil {
				results <- readErr
				return
			}
		}
	}()

	type queuedPacket struct {
		buffer      []byte
		destination *net.UDPAddr
		terminal    error
	}
	queue := make(chan queuedPacket, batchSize)
	bufferPool := make(chan []byte, batchSize+1)
	for range cap(bufferPool) {
		bufferPool <- make([]byte, maxDatagram+1)
	}
	go func() {
		defer workers.Done()
		buffers := make([][]byte, 0, batchSize)
		messages := make([]ipv4.Message, batchSize)
		messageBuffers := make([][]byte, batchSize)
		for index := range messages {
			messages[index].Buffers = messageBuffers[index : index+1]
		}
		for {
			buffers = buffers[:0]
			var first []byte
			select {
			case first = <-bufferPool:
			case <-shutdown:
				return
			}
			buffers = append(buffers, first)
		collectBuffers:
			for len(buffers) < batchSize {
				select {
				case buffer := <-bufferPool:
					buffers = append(buffers, buffer)
				default:
					break collectBuffers
				}
			}
			copy(messageBuffers[:len(buffers)], buffers)
			count, readErr := remotePackets.readBatch(
				messages[:len(buffers)],
			)
			if count < 0 || count > len(buffers) {
				readErr = errors.New(
					"carrier packet batch read returned an invalid count",
				)
				count = 0
			}
			if count == 0 && readErr == nil {
				readErr = errors.New(
					"carrier packet batch read made no progress",
				)
			}
			for index := count; index < len(buffers); index++ {
				bufferPool <- buffers[index]
			}
			if count == 0 && readErr != nil {
				select {
				case queue <- queuedPacket{
					terminal: fmt.Errorf(
						"carrier-to-local relay: %w",
						readErr,
					),
				}:
				case <-shutdown:
				}
				return
			}
			for index := range count {
				message := &messages[index]
				buffer := buffers[index]
				if message.N < 0 || message.N > len(buffer) {
					clear(buffer)
					bufferPool <- buffer
					readErr = errors.Join(
						readErr,
						errors.New(
							"carrier packet batch read returned an invalid size",
						),
					)
					for remainder := index + 1; remainder < count; remainder++ {
						bufferPool <- buffers[remainder]
					}
					break
				}
				if message.N > maxDatagram {
					clear(buffer[:message.N])
					bufferPool <- buffer
					continue
				}
				peerMu.RLock()
				destination := cloneUDPAddr(peer)
				peerMu.RUnlock()
				if destination == nil {
					clear(buffer[:message.N])
					bufferPool <- buffer
					continue
				}
				select {
				case queue <- queuedPacket{
					buffer:      buffer[:message.N],
					destination: destination,
				}:
				case <-shutdown:
					clear(buffer[:message.N])
					bufferPool <- buffer
					for remainder := index + 1; remainder < count; remainder++ {
						bufferPool <- buffers[remainder]
					}
					return
				}
			}
			for index := range len(buffers) {
				messageBuffers[index] = nil
				messages[index].N = 0
				messages[index].NN = 0
				messages[index].Flags = 0
				messages[index].Addr = nil
			}
			if readErr != nil {
				select {
				case queue <- queuedPacket{
					terminal: fmt.Errorf(
						"carrier-to-local relay: %w",
						readErr,
					),
				}:
				case <-shutdown:
				}
				return
			}
		}
	}()

	go func() {
		defer workers.Done()
		packets := make([]queuedPacket, 0, batchSize)
		messages := make([]ipv4.Message, batchSize)
		messageBuffers := make([][]byte, batchSize)
		for index := range messages {
			messages[index].Buffers = messageBuffers[index : index+1]
		}
		for {
			var first queuedPacket
			select {
			case first = <-queue:
			case <-shutdown:
				return
			}
			if first.terminal != nil {
				results <- first.terminal
				return
			}
			packets = append(packets, first)
			var terminal error
		collect:
			for len(packets) < batchSize {
				select {
				case packet := <-queue:
					if packet.terminal != nil {
						terminal = packet.terminal
						break collect
					}
					packets = append(packets, packet)
				default:
					break collect
				}
			}
			for index := range packets {
				messageBuffers[index] = packets[index].buffer
				messages[index].Addr = packets[index].destination
			}
			err := writeAllRelayMessages(
				localPackets,
				messages[:len(packets)],
			)
			for _, packet := range packets {
				clear(packet.buffer)
				bufferPool <- packet.buffer[:cap(packet.buffer)]
			}
			for index := range len(packets) {
				messageBuffers[index] = nil
				messages[index].N = 0
				messages[index].NN = 0
				messages[index].Flags = 0
				messages[index].Addr = nil
			}
			packets = packets[:0]
			if err != nil {
				results <- fmt.Errorf(
					"carrier-to-local UDP write: %w",
					err,
				)
				return
			}
			if terminal != nil {
				results <- terminal
				return
			}
		}
	}()

	var result error
	select {
	case <-ctx.Done():
		result = context.Cause(ctx)
	case err := <-results:
		result = err
	}
	stopWorkers()
	_ = local.Close()
	_ = remote.Close()
	workers.Wait()
	return result
}

func cloneUDPAddr(address *net.UDPAddr) *net.UDPAddr {
	if address == nil {
		return nil
	}
	clone := *address
	clone.IP = append(net.IP(nil), address.IP...)
	return &clone
}

func sameUDPAddr(first, second *net.UDPAddr) bool {
	return first != nil && second != nil &&
		first.Port == second.Port &&
		first.Zone == second.Zone &&
		first.IP.Equal(second.IP)
}
