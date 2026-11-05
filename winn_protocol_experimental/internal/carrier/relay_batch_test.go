package carrier

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/net/ipv4"
)

func TestRelayBatchFallbackIsStickyInBothDirections(t *testing.T) {
	local := listenRelayUDP(t)
	peer, err := net.DialUDP("udp", nil, local.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatal(err)
	}
	defer peer.Close()

	batch := &unsupportedRelayBatchConn{}
	packetIO := newRelayPacketIO(
		local,
		peer.LocalAddr().(*net.UDPAddr),
		func(net.PacketConn, *net.UDPAddr) relayBatchConn { return batch },
	)
	messages := makeRelayMessages(4, 64)
	for _, packet := range []string{"one", "two"} {
		if _, err := peer.Write([]byte(packet)); err != nil {
			t.Fatal(err)
		}
		count, err := packetIO.readBatch(messages)
		if err != nil {
			t.Fatal(err)
		}
		if count != 1 || string(messages[0].Buffers[0][:messages[0].N]) != packet {
			t.Fatalf("fallback read = %d, %q", count, messages[0].Buffers[0][:messages[0].N])
		}
	}
	if calls := batch.readCalls.Load(); calls != 1 {
		t.Fatalf("unsupported ReadBatch called %d times; want 1", calls)
	}

	destination := peer.LocalAddr().(*net.UDPAddr)
	for _, packet := range []string{"three", "four"} {
		messages[0] = ipv4.Message{
			Buffers: [][]byte{[]byte(packet)},
			Addr:    destination,
		}
		count, err := packetIO.writeBatch(messages[:1])
		if err != nil {
			t.Fatal(err)
		}
		if count != 1 {
			t.Fatalf("fallback write count = %d; want 1", count)
		}
		_ = peer.SetReadDeadline(time.Now().Add(time.Second))
		buffer := make([]byte, 64)
		count, err = peer.Read(buffer)
		if err != nil {
			t.Fatal(err)
		}
		if string(buffer[:count]) != packet {
			t.Fatalf("fallback write = %q; want %q", buffer[:count], packet)
		}
	}
	if calls := batch.writeCalls.Load(); calls != 1 {
		t.Fatalf("unsupported WriteBatch called %d times; want 1", calls)
	}
}

func TestConfigureRelaySocketBuffersCallOrderAndErrors(t *testing.T) {
	failure := errors.New("scripted socket-buffer failure")
	tests := []struct {
		name        string
		failAt      string
		errorStage  string
		wantCalls   []relaySocketBufferCall
		wantFailure bool
	}{
		{
			name: "success",
			wantCalls: []relaySocketBufferCall{
				{endpoint: "local", operation: "read", bytes: 1 << 20},
				{endpoint: "local", operation: "write", bytes: 1 << 20},
				{endpoint: "remote", operation: "read", bytes: 1 << 20},
				{endpoint: "remote", operation: "write", bytes: 1 << 20},
			},
		},
		{
			name:        "local read failure",
			failAt:      "local/read",
			errorStage:  "configure local relay UDP read buffer",
			wantFailure: true,
			wantCalls: []relaySocketBufferCall{
				{endpoint: "local", operation: "read", bytes: 1 << 20},
			},
		},
		{
			name:        "local write failure",
			failAt:      "local/write",
			errorStage:  "configure local relay UDP write buffer",
			wantFailure: true,
			wantCalls: []relaySocketBufferCall{
				{endpoint: "local", operation: "read", bytes: 1 << 20},
				{endpoint: "local", operation: "write", bytes: 1 << 20},
			},
		},
		{
			name:        "remote read failure",
			failAt:      "remote/read",
			errorStage:  "configure carrier UDP read buffer",
			wantFailure: true,
			wantCalls: []relaySocketBufferCall{
				{endpoint: "local", operation: "read", bytes: 1 << 20},
				{endpoint: "local", operation: "write", bytes: 1 << 20},
				{endpoint: "remote", operation: "read", bytes: 1 << 20},
			},
		},
		{
			name:        "remote write failure",
			failAt:      "remote/write",
			errorStage:  "configure carrier UDP write buffer",
			wantFailure: true,
			wantCalls: []relaySocketBufferCall{
				{endpoint: "local", operation: "read", bytes: 1 << 20},
				{endpoint: "local", operation: "write", bytes: 1 << 20},
				{endpoint: "remote", operation: "read", bytes: 1 << 20},
				{endpoint: "remote", operation: "write", bytes: 1 << 20},
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			recorder := &relaySocketBufferRecorder{
				failAt: test.failAt,
				fail:   failure,
			}
			local := &recordingRelaySocketBufferSetter{
				endpoint: "local",
				recorder: recorder,
			}
			remote := &relaySocketBufferPacketConn{
				fakePacketConn: newFakePacketConn(),
				setter: &recordingRelaySocketBufferSetter{
					endpoint: "remote",
					recorder: recorder,
				},
			}
			err := configureRelaySocketBuffers(local, remote, 1<<20)
			if test.wantFailure {
				if !errors.Is(err, failure) {
					t.Fatalf("configure error = %v; want wrapped failure", err)
				}
				if !strings.Contains(err.Error(), test.errorStage) {
					t.Fatalf(
						"configure error = %q; want stage %q",
						err,
						test.errorStage,
					)
				}
			} else if err != nil {
				t.Fatal(err)
			}
			calls := recorder.snapshot()
			if fmt.Sprint(calls) != fmt.Sprint(test.wantCalls) {
				t.Fatalf("setter calls = %v; want %v", calls, test.wantCalls)
			}
		})
	}
}

func TestConfigureRelaySocketBuffersBoundsAndCompatibility(t *testing.T) {
	recorder := &relaySocketBufferRecorder{}
	local := &recordingRelaySocketBufferSetter{
		endpoint: "local",
		recorder: recorder,
	}
	compatible := &relaySocketBufferPacketConn{
		fakePacketConn: newFakePacketConn(),
		setter: &recordingRelaySocketBufferSetter{
			endpoint: "remote",
			recorder: recorder,
		},
	}
	for _, test := range []struct {
		name    string
		bytes   int
		remote  net.PacketConn
		wantErr bool
		calls   int
	}{
		{
			name:   "disabled accepts incompatible carrier",
			bytes:  0,
			remote: newFakePacketConn(),
		},
		{
			name:    "negative rejected",
			bytes:   -1,
			remote:  compatible,
			wantErr: true,
		},
		{
			name:    "above maximum rejected",
			bytes:   MaxRelaySocketBufferBytes + 1,
			remote:  compatible,
			wantErr: true,
		},
		{
			name:    "positive requires compatible carrier before mutation",
			bytes:   1,
			remote:  newFakePacketConn(),
			wantErr: true,
		},
		{
			name:   "minimum positive accepted",
			bytes:  1,
			remote: compatible,
			calls:  4,
		},
		{
			name:   "maximum accepted",
			bytes:  MaxRelaySocketBufferBytes,
			remote: compatible,
			calls:  4,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			recorder.reset()
			err := configureRelaySocketBuffers(local, test.remote, test.bytes)
			if (err != nil) != test.wantErr {
				t.Fatalf("configure error = %v; wantErr %v", err, test.wantErr)
			}
			if calls := len(recorder.snapshot()); calls != test.calls {
				t.Fatalf("setter calls = %d; want %d", calls, test.calls)
			}
		})
	}
}

func TestConfigureRelaySocketBuffersConcurrent(t *testing.T) {
	recorder := &relaySocketBufferRecorder{}
	local := &recordingRelaySocketBufferSetter{
		endpoint: "local",
		recorder: recorder,
	}
	remote := &relaySocketBufferPacketConn{
		fakePacketConn: newFakePacketConn(),
		setter: &recordingRelaySocketBufferSetter{
			endpoint: "remote",
			recorder: recorder,
		},
	}
	const workers = 32
	const iterations = 50
	var group sync.WaitGroup
	group.Add(workers)
	failures := make(chan error, workers)
	for worker := range workers {
		go func() {
			defer group.Done()
			for iteration := range iterations {
				size := 1 + (worker+iteration)%MaxRelaySocketBufferBytes
				if err := configureRelaySocketBuffers(local, remote, size); err != nil {
					failures <- err
					return
				}
			}
		}()
	}
	group.Wait()
	close(failures)
	for err := range failures {
		t.Fatal(err)
	}
	if calls := len(recorder.snapshot()); calls != workers*iterations*4 {
		t.Fatalf("setter calls = %d; want %d", calls, workers*iterations*4)
	}
}

func TestRelayLocalUDPSocketBufferFailureStopsBeforeBatchSetup(t *testing.T) {
	local := listenRelayUDP(t)
	failure := errors.New("remote socket tuning failed")
	recorder := &relaySocketBufferRecorder{
		failAt: "remote/read",
		fail:   failure,
	}
	remote := &relaySocketBufferPacketConn{
		fakePacketConn: newFakePacketConn(),
		setter: &recordingRelaySocketBufferSetter{
			endpoint: "remote",
			recorder: recorder,
		},
	}
	var factoryCalls atomic.Int64
	factory := func(net.PacketConn, *net.UDPAddr) relayBatchConn {
		factoryCalls.Add(1)
		return nil
	}
	err := relayLocalUDP(
		context.Background(),
		local,
		remote,
		RelayConfig{
			MaxDatagram:       1200,
			ExpectedLocalPeer: &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 41001},
			SocketBufferBytes: 4096,
		},
		factory,
		factory,
	)
	if !errors.Is(err, failure) {
		t.Fatalf("relay error = %v; want wrapped tuning failure", err)
	}
	if calls := factoryCalls.Load(); calls != 0 {
		t.Fatalf("batch factories called %d times after tuning failure", calls)
	}
	_ = remote.Close()
}

func TestRelayBatchPartialUnsupportedDoesNotReorderOrDuplicate(t *testing.T) {
	local := listenRelayUDP(t)
	receiver := listenRelayUDP(t)
	defer receiver.Close()
	destination := receiver.LocalAddr().(*net.UDPAddr)

	batch := &partialUnsupportedRelayBatchConn{
		connection: local,
		writeCount: 3,
	}
	packetIO := newRelayPacketIO(
		local,
		destination,
		func(net.PacketConn, *net.UDPAddr) relayBatchConn { return batch },
	)
	const packetCount = 12
	messages := make([]ipv4.Message, packetCount)
	for index := range messages {
		messages[index] = ipv4.Message{
			Buffers: [][]byte{[]byte(fmt.Sprintf("%03d", index))},
			Addr:    destination,
		}
	}
	for written := 0; written < len(messages); {
		count, err := packetIO.writeBatch(messages[written:])
		if err != nil {
			t.Fatal(err)
		}
		if count < 1 {
			t.Fatal("write fallback made no progress")
		}
		written += count
	}
	if calls := batch.writeCalls.Load(); calls != 1 {
		t.Fatalf("partial unsupported WriteBatch called %d times; want 1", calls)
	}

	received := make([]string, 0, packetCount)
	buffer := make([]byte, 64)
	for range packetCount {
		_ = receiver.SetReadDeadline(time.Now().Add(time.Second))
		count, _, err := receiver.ReadFromUDP(buffer)
		if err != nil {
			t.Fatal(err)
		}
		received = append(received, string(buffer[:count]))
	}
	for index, packet := range received {
		expected := fmt.Sprintf("%03d", index)
		if packet != expected {
			t.Fatalf("packet %d = %q; want %q (received %v)", index, packet, expected, received)
		}
	}
}

func TestRelayBatchConnectedRemoteSocketPreservesOrder(t *testing.T) {
	receiver := listenRelayUDP(t)
	raw, err := net.DialUDP(
		"udp",
		nil,
		receiver.LocalAddr().(*net.UDPAddr),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	connection := &connectedRelayTestPacketConn{UDPConn: raw}
	batch := newRelayBatchConn(connection, nil)
	if batch == nil {
		t.Fatal("connected UDP wrapper was not recognized as batch-capable")
	}
	packetIO := newRelayPacketIO(
		connection,
		nil,
		func(net.PacketConn, *net.UDPAddr) relayBatchConn { return batch },
	)

	const packetCount = 16
	messages := make([]ipv4.Message, packetCount)
	for index := range messages {
		messages[index].Buffers = [][]byte{
			[]byte(fmt.Sprintf("out-%03d", index)),
		}
		// A connected UDP socket intentionally uses a nil destination.
	}
	if err := writeAllRelayMessages(packetIO, messages); err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, 64)
	for index := range packetCount {
		_ = receiver.SetReadDeadline(time.Now().Add(time.Second))
		count, _, err := receiver.ReadFromUDP(buffer)
		if err != nil {
			t.Fatal(err)
		}
		expected := fmt.Sprintf("out-%03d", index)
		if got := string(buffer[:count]); got != expected {
			t.Fatalf("outbound packet %d = %q; want %q", index, got, expected)
		}
	}

	sender := raw.LocalAddr().(*net.UDPAddr)
	for index := range packetCount {
		if _, err := receiver.WriteToUDP(
			[]byte(fmt.Sprintf("in-%03d", index)),
			sender,
		); err != nil {
			t.Fatal(err)
		}
	}
	readMessages := makeRelayMessages(packetCount, 64)
	received := make([]string, 0, packetCount)
	for len(received) < packetCount {
		count, err := packetIO.readBatch(readMessages)
		if err != nil {
			t.Fatal(err)
		}
		for index := range count {
			received = append(
				received,
				string(readMessages[index].Buffers[0][:readMessages[index].N]),
			)
		}
	}
	for index, packet := range received {
		expected := fmt.Sprintf("in-%03d", index)
		if packet != expected {
			t.Fatalf("inbound packet %d = %q; want %q", index, packet, expected)
		}
	}
}

func TestRelayLocalUDPBatchPreservesPeerPinAndOrder(t *testing.T) {
	local := listenRelayUDP(t)
	expected := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 41001}
	attacker := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 41002}
	const packetCount = 48
	packets := make([]scriptedRelayPacket, 0, packetCount*2)
	expectedPackets := make([]string, 0, packetCount)
	for index := range packetCount {
		allowed := fmt.Sprintf("allowed-%03d", index)
		packets = append(packets,
			scriptedRelayPacket{
				data:   []byte(fmt.Sprintf("attacker-%03d", index)),
				sender: attacker,
			},
			scriptedRelayPacket{data: []byte(allowed), sender: expected},
		)
		expectedPackets = append(expectedPackets, allowed)
	}
	batch := newScriptedRelayBatchConn(packets)
	remote := newFakePacketConn()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- relayLocalUDP(
			ctx,
			local,
			remote,
			RelayConfig{
				MaxDatagram:       1200,
				ExpectedLocalPeer: expected,
				BatchSize:         32,
			},
			func(net.PacketConn, *net.UDPAddr) relayBatchConn { return batch },
			noRelayBatch,
		)
	}()
	waitForWrites(t, remote, packetCount)
	cancel()
	batch.close()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("batched relay did not stop")
	}

	remote.mu.Lock()
	writes := make([][]byte, len(remote.writes))
	for index := range remote.writes {
		writes[index] = append([]byte(nil), remote.writes[index]...)
	}
	remote.mu.Unlock()
	if len(writes) != packetCount {
		t.Fatalf("relayed %d packets; want %d", len(writes), packetCount)
	}
	for index, packet := range writes {
		if string(packet) != expectedPackets[index] {
			t.Fatalf(
				"packet %d = %q; want %q",
				index,
				packet,
				expectedPackets[index],
			)
		}
	}
	if calls := batch.readCalls.Load(); calls >= packetCount {
		t.Fatalf("ReadBatch calls = %d; batching did not occur", calls)
	}
}

func TestRelayLocalUDPBatchDrainsPacketsBeforeCarrierError(t *testing.T) {
	local := listenRelayUDP(t)
	peer, err := net.DialUDP("udp", nil, local.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatal(err)
	}
	defer peer.Close()
	const packetCount = 40
	terminal := errors.New("scripted carrier failure")
	remote := newSequencePacketConn(packetCount, terminal)
	recorder := &recordingRelayBatchConn{
		read: newRelayBatchConn(local, peer.LocalAddr().(*net.UDPAddr)),
	}
	err = relayLocalUDP(
		context.Background(),
		local,
		remote,
		RelayConfig{
			MaxDatagram:       1200,
			ExpectedLocalPeer: peer.LocalAddr().(*net.UDPAddr),
			BatchSize:         packetCount,
		},
		func(net.PacketConn, *net.UDPAddr) relayBatchConn { return recorder },
		noRelayBatch,
	)
	if !errors.Is(err, terminal) {
		t.Fatalf("relay error = %v; want carrier error", err)
	}
	writes := recorder.snapshot()
	if len(writes) != packetCount {
		t.Fatalf("wrote %d packets before carrier error; want %d", len(writes), packetCount)
	}
	for index, packet := range writes {
		expected := fmt.Sprintf("%03d", index)
		if packet != expected {
			t.Fatalf("packet %d = %q; want %q", index, packet, expected)
		}
	}
}

func TestRelayLocalUDPBatchIPv6(t *testing.T) {
	local, err := net.ListenUDP(
		"udp6",
		&net.UDPAddr{IP: net.ParseIP("::1")},
	)
	if err != nil {
		t.Skipf("IPv6 loopback is unavailable: %v", err)
	}
	peer, err := net.DialUDP("udp6", nil, local.LocalAddr().(*net.UDPAddr))
	if err != nil {
		_ = local.Close()
		t.Skipf("IPv6 loopback dial is unavailable: %v", err)
	}
	defer peer.Close()
	remote := newFakePacketConn()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- RelayLocalUDP(ctx, local, remote, RelayConfig{
			MaxDatagram:       1200,
			ExpectedLocalPeer: peer.LocalAddr().(*net.UDPAddr),
		})
	}()
	if _, err := peer.Write([]byte("v6-to-carrier")); err != nil {
		t.Fatal(err)
	}
	waitForWrites(t, remote, 1)
	remote.reads <- packetResult{data: []byte("v6-to-local")}
	_ = peer.SetReadDeadline(time.Now().Add(time.Second))
	buffer := make([]byte, 64)
	count, err := peer.Read(buffer)
	if err != nil {
		t.Fatal(err)
	}
	if got := string(buffer[:count]); got != "v6-to-local" {
		t.Fatalf("IPv6 reply = %q", got)
	}
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("IPv6 batch relay did not stop")
	}
}

func TestRelayBatchUnsupportedClassification(t *testing.T) {
	for _, test := range []struct {
		name string
		err  error
		want bool
	}{
		{
			name: "sentinel",
			err:  fmt.Errorf("wrapped: %w", errRelayBatchUnsupported),
			want: true,
		},
		{
			name: "errors unsupported",
			err:  fmt.Errorf("wrapped: %w", errors.ErrUnsupported),
			want: true,
		},
		{
			name: "xnet platform stub",
			err: &net.OpError{
				Op:  "read",
				Net: "udp",
				Err: errors.New("not implemented on windows/amd64"),
			},
			want: true,
		},
		{
			name: "ordinary network error",
			err:  errors.New("connection refused"),
			want: false,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := isRelayBatchUnsupported(test.err); got != test.want {
				t.Fatalf("isRelayBatchUnsupported(%v) = %v; want %v", test.err, got, test.want)
			}
		})
	}
}

func TestRelayLocalUDPIdleTimeoutWithBatchFallback(t *testing.T) {
	local := listenRelayUDP(t)
	remote := newFakePacketConn()
	batch := &unsupportedRelayBatchConn{}
	err := relayLocalUDP(
		context.Background(),
		local,
		remote,
		RelayConfig{
			MaxDatagram: 1200,
			IdleTimeout: 20 * time.Millisecond,
			BatchSize:   8,
		},
		func(net.PacketConn, *net.UDPAddr) relayBatchConn { return batch },
		noRelayBatch,
	)
	var netError net.Error
	if !errors.As(err, &netError) || !netError.Timeout() {
		t.Fatalf("relay error = %v; want idle timeout", err)
	}
}

func TestRelayLocalUDPRejectsUnboundedBatch(t *testing.T) {
	local := listenRelayUDP(t)
	remote := newFakePacketConn()
	err := RelayLocalUDP(
		context.Background(),
		local,
		remote,
		RelayConfig{BatchSize: MaxRelayBatchSize + 1},
	)
	if err == nil {
		t.Fatal("oversized relay batch unexpectedly accepted")
	}
	_ = local.Close()
	_ = remote.Close()
}

func BenchmarkRelayLocalUDPBatchIngress(b *testing.B) {
	for _, batchSize := range []int{1, DefaultRelayBatchSize} {
		b.Run(fmt.Sprintf("Batch%d", batchSize), func(b *testing.B) {
			local, err := net.ListenUDP(
				"udp",
				&net.UDPAddr{IP: net.ParseIP("127.0.0.1")},
			)
			if err != nil {
				b.Fatal(err)
			}
			source := newGeneratedRelayBatchConn(b.N)
			ctx, cancel := context.WithCancel(context.Background())
			remote := newBenchmarkRelayPacketConn(b.N, cancel, source.close)
			remoteBatch := &benchmarkRemoteBatchConn{connection: remote}
			b.ReportAllocs()
			b.SetBytes(1200)
			b.ResetTimer()
			err = relayLocalUDP(
				ctx,
				local,
				remote,
				RelayConfig{
					MaxDatagram:       1200,
					ExpectedLocalPeer: source.sender,
					BatchSize:         batchSize,
				},
				func(net.PacketConn, *net.UDPAddr) relayBatchConn {
					source.batchSize = batchSize
					return source
				},
				func(net.PacketConn, *net.UDPAddr) relayBatchConn {
					return remoteBatch
				},
			)
			b.StopTimer()
			if !errors.Is(err, context.Canceled) && !errors.Is(err, net.ErrClosed) {
				b.Fatal(err)
			}
			if count := remote.writes.Load(); count != int64(b.N) {
				b.Fatalf("relayed %d packets; want %d", count, b.N)
			}
			if batchSize > 1 && b.N > 1 &&
				remoteBatch.writeCalls.Load() >= int64(b.N) {
				b.Fatalf(
					"remote WriteBatch called %d times for %d packets",
					remoteBatch.writeCalls.Load(),
					b.N,
				)
			}
			b.ReportMetric(
				float64(
					source.readCalls.Load()+
						remoteBatch.writeCalls.Load(),
				)/float64(b.N),
				"batch-calls/pkt",
			)
		})
	}
}

type unsupportedRelayBatchConn struct {
	readCalls  atomic.Int64
	writeCalls atomic.Int64
}

type relaySocketBufferCall struct {
	endpoint  string
	operation string
	bytes     int
}

type relaySocketBufferRecorder struct {
	mu     sync.Mutex
	calls  []relaySocketBufferCall
	failAt string
	fail   error
}

func (recorder *relaySocketBufferRecorder) record(
	endpoint string,
	operation string,
	bytes int,
) error {
	recorder.mu.Lock()
	defer recorder.mu.Unlock()
	recorder.calls = append(recorder.calls, relaySocketBufferCall{
		endpoint:  endpoint,
		operation: operation,
		bytes:     bytes,
	})
	if recorder.failAt == endpoint+"/"+operation {
		return recorder.fail
	}
	return nil
}

func (recorder *relaySocketBufferRecorder) snapshot() []relaySocketBufferCall {
	recorder.mu.Lock()
	defer recorder.mu.Unlock()
	return append([]relaySocketBufferCall(nil), recorder.calls...)
}

func (recorder *relaySocketBufferRecorder) reset() {
	recorder.mu.Lock()
	recorder.calls = nil
	recorder.mu.Unlock()
}

type recordingRelaySocketBufferSetter struct {
	endpoint string
	recorder *relaySocketBufferRecorder
}

func (setter *recordingRelaySocketBufferSetter) SetReadBuffer(bytes int) error {
	return setter.recorder.record(setter.endpoint, "read", bytes)
}

func (setter *recordingRelaySocketBufferSetter) SetWriteBuffer(bytes int) error {
	return setter.recorder.record(setter.endpoint, "write", bytes)
}

type relaySocketBufferPacketConn struct {
	*fakePacketConn
	setter *recordingRelaySocketBufferSetter
}

func (connection *relaySocketBufferPacketConn) SetReadBuffer(bytes int) error {
	return connection.setter.SetReadBuffer(bytes)
}

func (connection *relaySocketBufferPacketConn) SetWriteBuffer(bytes int) error {
	return connection.setter.SetWriteBuffer(bytes)
}

type connectedRelayTestPacketConn struct {
	*net.UDPConn
}

func (connection *connectedRelayTestPacketConn) ReadFrom(
	packet []byte,
) (int, net.Addr, error) {
	count, err := connection.Read(packet)
	return count, connection.RemoteAddr(), err
}

func (connection *connectedRelayTestPacketConn) WriteTo(
	packet []byte,
	_ net.Addr,
) (int, error) {
	return connection.Write(packet)
}

func (connection *unsupportedRelayBatchConn) ReadBatch(
	[]ipv4.Message,
	int,
) (int, error) {
	connection.readCalls.Add(1)
	return 0, errRelayBatchUnsupported
}

func (connection *unsupportedRelayBatchConn) WriteBatch(
	[]ipv4.Message,
	int,
) (int, error) {
	connection.writeCalls.Add(1)
	return 0, errRelayBatchUnsupported
}

type partialUnsupportedRelayBatchConn struct {
	connection *net.UDPConn
	writeCount int
	writeCalls atomic.Int64
}

func (*partialUnsupportedRelayBatchConn) ReadBatch(
	[]ipv4.Message,
	int,
) (int, error) {
	return 0, errRelayBatchUnsupported
}

func (connection *partialUnsupportedRelayBatchConn) WriteBatch(
	messages []ipv4.Message,
	_ int,
) (int, error) {
	connection.writeCalls.Add(1)
	count := min(connection.writeCount, len(messages))
	for index := range count {
		destination := messages[index].Addr.(*net.UDPAddr)
		if _, err := connection.connection.WriteToUDP(
			messages[index].Buffers[0],
			destination,
		); err != nil {
			return index, err
		}
	}
	return count, errRelayBatchUnsupported
}

type scriptedRelayPacket struct {
	data   []byte
	sender *net.UDPAddr
}

type scriptedRelayBatchConn struct {
	mu        sync.Mutex
	packets   []scriptedRelayPacket
	closed    chan struct{}
	closeOnce sync.Once
	readCalls atomic.Int64
}

func newScriptedRelayBatchConn(
	packets []scriptedRelayPacket,
) *scriptedRelayBatchConn {
	return &scriptedRelayBatchConn{
		packets: packets,
		closed:  make(chan struct{}),
	}
}

func (connection *scriptedRelayBatchConn) ReadBatch(
	messages []ipv4.Message,
	_ int,
) (int, error) {
	connection.readCalls.Add(1)
	connection.mu.Lock()
	count := min(len(messages), len(connection.packets))
	if count > 0 {
		for index := range count {
			packet := connection.packets[index]
			messages[index].N = copy(messages[index].Buffers[0], packet.data)
			messages[index].Addr = cloneUDPAddr(packet.sender)
		}
		connection.packets = connection.packets[count:]
		connection.mu.Unlock()
		return count, nil
	}
	connection.mu.Unlock()
	<-connection.closed
	return 0, net.ErrClosed
}

func (*scriptedRelayBatchConn) WriteBatch(
	[]ipv4.Message,
	int,
) (int, error) {
	return 0, errRelayBatchUnsupported
}

func (connection *scriptedRelayBatchConn) close() {
	connection.closeOnce.Do(func() { close(connection.closed) })
}

type recordingRelayBatchConn struct {
	read relayBatchConn

	mu     sync.Mutex
	writes []string
}

func (connection *recordingRelayBatchConn) ReadBatch(
	messages []ipv4.Message,
	flags int,
) (int, error) {
	return connection.read.ReadBatch(messages, flags)
}

func (connection *recordingRelayBatchConn) WriteBatch(
	messages []ipv4.Message,
	_ int,
) (int, error) {
	connection.mu.Lock()
	defer connection.mu.Unlock()
	for _, message := range messages {
		connection.writes = append(
			connection.writes,
			string(message.Buffers[0]),
		)
	}
	return len(messages), nil
}

func (connection *recordingRelayBatchConn) snapshot() []string {
	connection.mu.Lock()
	defer connection.mu.Unlock()
	return append([]string(nil), connection.writes...)
}

type sequencePacketConn struct {
	mu       sync.Mutex
	next     int
	total    int
	terminal error
	closed   bool
}

func newSequencePacketConn(total int, terminal error) *sequencePacketConn {
	return &sequencePacketConn{total: total, terminal: terminal}
}

func (connection *sequencePacketConn) ReadFrom(
	buffer []byte,
) (int, net.Addr, error) {
	connection.mu.Lock()
	defer connection.mu.Unlock()
	if connection.closed {
		return 0, nil, net.ErrClosed
	}
	if connection.next >= connection.total {
		return 0, nil, connection.terminal
	}
	packet := fmt.Sprintf("%03d", connection.next)
	connection.next++
	return copy(buffer, packet), fixedAddr("sequence"), nil
}

func (*sequencePacketConn) WriteTo(packet []byte, _ net.Addr) (int, error) {
	return len(packet), nil
}

func (connection *sequencePacketConn) Close() error {
	connection.mu.Lock()
	connection.closed = true
	connection.mu.Unlock()
	return nil
}

func (*sequencePacketConn) LocalAddr() net.Addr              { return fixedAddr("sequence") }
func (*sequencePacketConn) SetDeadline(time.Time) error      { return nil }
func (*sequencePacketConn) SetReadDeadline(time.Time) error  { return nil }
func (*sequencePacketConn) SetWriteDeadline(time.Time) error { return nil }

type generatedRelayBatchConn struct {
	mu        sync.Mutex
	remaining int
	sequence  int
	batchSize int
	sender    *net.UDPAddr
	closed    chan struct{}
	closeOnce sync.Once
	readCalls atomic.Int64
}

func newGeneratedRelayBatchConn(total int) *generatedRelayBatchConn {
	return &generatedRelayBatchConn{
		remaining: total,
		sender: &net.UDPAddr{
			IP:   net.ParseIP("127.0.0.1"),
			Port: 42001,
		},
		closed: make(chan struct{}),
	}
}

func (connection *generatedRelayBatchConn) ReadBatch(
	messages []ipv4.Message,
	_ int,
) (int, error) {
	connection.readCalls.Add(1)
	connection.mu.Lock()
	count := min(len(messages), connection.batchSize, connection.remaining)
	if count > 0 {
		for index := range count {
			packet := messages[index].Buffers[0]
			for offset := range 1200 {
				packet[offset] = byte(connection.sequence + offset)
			}
			messages[index].N = 1200
			messages[index].Addr = connection.sender
			connection.sequence++
		}
		connection.remaining -= count
		connection.mu.Unlock()
		return count, nil
	}
	connection.mu.Unlock()
	<-connection.closed
	return 0, net.ErrClosed
}

func (*generatedRelayBatchConn) WriteBatch(
	[]ipv4.Message,
	int,
) (int, error) {
	return 0, errRelayBatchUnsupported
}

func (connection *generatedRelayBatchConn) close() {
	connection.closeOnce.Do(func() { close(connection.closed) })
}

type benchmarkRelayPacketConn struct {
	target  int64
	writes  atomic.Int64
	cancel  context.CancelFunc
	closeIn func()
	closed  chan struct{}
	once    sync.Once
}

func newBenchmarkRelayPacketConn(
	target int,
	cancel context.CancelFunc,
	closeInput func(),
) *benchmarkRelayPacketConn {
	return &benchmarkRelayPacketConn{
		target:  int64(target),
		cancel:  cancel,
		closeIn: closeInput,
		closed:  make(chan struct{}),
	}
}

func (connection *benchmarkRelayPacketConn) ReadFrom(
	[]byte,
) (int, net.Addr, error) {
	<-connection.closed
	return 0, nil, net.ErrClosed
}

func (connection *benchmarkRelayPacketConn) WriteTo(
	packet []byte,
	_ net.Addr,
) (int, error) {
	count := connection.writes.Add(1)
	if count == connection.target {
		connection.cancel()
		connection.closeIn()
	}
	return len(packet), nil
}

func (connection *benchmarkRelayPacketConn) Close() error {
	connection.once.Do(func() { close(connection.closed) })
	return nil
}

func (*benchmarkRelayPacketConn) LocalAddr() net.Addr {
	return fixedAddr("benchmark")
}
func (*benchmarkRelayPacketConn) SetDeadline(time.Time) error      { return nil }
func (*benchmarkRelayPacketConn) SetReadDeadline(time.Time) error  { return nil }
func (*benchmarkRelayPacketConn) SetWriteDeadline(time.Time) error { return nil }

type benchmarkRemoteBatchConn struct {
	connection *benchmarkRelayPacketConn
	writeCalls atomic.Int64
}

func (connection *benchmarkRemoteBatchConn) ReadBatch(
	[]ipv4.Message,
	int,
) (int, error) {
	<-connection.connection.closed
	return 0, net.ErrClosed
}

func (connection *benchmarkRemoteBatchConn) WriteBatch(
	messages []ipv4.Message,
	_ int,
) (int, error) {
	connection.writeCalls.Add(1)
	count := connection.connection.writes.Add(int64(len(messages)))
	if count == connection.connection.target {
		connection.connection.cancel()
		connection.connection.closeIn()
	}
	return len(messages), nil
}

func makeRelayMessages(count, size int) []ipv4.Message {
	messages := make([]ipv4.Message, count)
	for index := range messages {
		messages[index].Buffers = [][]byte{make([]byte, size)}
	}
	return messages
}

func listenRelayUDP(t testing.TB) *net.UDPConn {
	t.Helper()
	connection, err := net.ListenUDP(
		"udp",
		&net.UDPAddr{IP: net.ParseIP("127.0.0.1")},
	)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = connection.Close() })
	return connection
}

func noRelayBatch(net.PacketConn, *net.UDPAddr) relayBatchConn {
	return nil
}
