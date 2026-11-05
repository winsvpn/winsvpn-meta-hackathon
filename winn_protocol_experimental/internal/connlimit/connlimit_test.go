package connlimit

import (
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func serve(t *testing.T, listener net.Listener) *sync.WaitGroup {
	t.Helper()
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		var held []net.Conn
		defer func() {
			for _, conn := range held {
				_ = conn.Close()
			}
		}()
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			held = append(held, conn)
		}
	}()
	return &wg
}

// dialAndHold opens n connections and reports how many are still alive, which
// is the only observable that matters: a dial succeeds off the kernel backlog
// even when the server drops the connection immediately.
func dialAndHold(t *testing.T, address string, n int) (int, []net.Conn) {
	t.Helper()
	var alive atomic.Int64
	conns := make([]net.Conn, 0, n)
	var mu sync.Mutex
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			conn, err := net.DialTimeout("tcp", address, 5*time.Second)
			if err != nil {
				return
			}
			mu.Lock()
			conns = append(conns, conn)
			mu.Unlock()
		}()
	}
	wg.Wait()

	var check sync.WaitGroup
	for _, conn := range conns {
		check.Add(1)
		go func(conn net.Conn) {
			defer check.Done()
			_ = conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
			var buffer [1]byte
			_, err := conn.Read(buffer[:])
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				alive.Add(1)
			}
		}(conn)
	}
	check.Wait()
	return int(alive.Load()), conns
}

// TestPerSourceCapBoundsOneFlooder is the P1-5 regression test. Before this
// package the measured answer was 3000 of 3000 parked from one source.
func TestPerSourceCapBoundsOneFlooder(t *testing.T) {
	inner, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	var rejected atomic.Int64
	limited, err := Listen(inner, Options{
		MaxTotal:   256,
		MaxPerIP:   8,
		OnRejected: func() { rejected.Add(1) },
	})
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer limited.Close()
	wg := serve(t, limited)

	alive, conns := dialAndHold(t, inner.Addr().String(), 100)
	if alive > 8 {
		t.Fatalf("one source held %d concurrent connections, cap is 8", alive)
	}
	if alive == 0 {
		t.Fatal("the cap rejected every connection, including the permitted ones")
	}
	if rejected.Load() == 0 {
		t.Fatal("no rejection was reported")
	}
	for _, conn := range conns {
		_ = conn.Close()
	}
	_ = limited.Close()
	wg.Wait()
}

// TestSlotsAreReturnedOnClose: a cap that leaks slots is a self-inflicted
// outage, so closing must free capacity for the next peer.
func TestSlotsAreReturnedOnClose(t *testing.T) {
	inner, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	limited, err := Listen(inner, Options{MaxTotal: 64, MaxPerIP: 2})
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer limited.Close()
	accepted := make(chan net.Conn, 16)
	go func() {
		for {
			conn, err := limited.Accept()
			if err != nil {
				return
			}
			accepted <- conn
		}
	}()

	address := inner.Addr().String()
	first, err := net.DialTimeout("tcp", address, 5*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	second, err := net.DialTimeout("tcp", address, 5*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	var served []net.Conn
	for i := 0; i < 2; i++ {
		select {
		case conn := <-accepted:
			served = append(served, conn)
		case <-time.After(5 * time.Second):
			t.Fatal("two connections within the cap were not accepted")
		}
	}
	// Free both slots, then prove a third peer can now be served.
	for _, conn := range served {
		_ = conn.Close()
	}
	_ = first.Close()
	_ = second.Close()

	third, err := net.DialTimeout("tcp", address, 5*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer third.Close()
	select {
	case conn := <-accepted:
		_ = conn.Close()
	case <-time.After(5 * time.Second):
		t.Fatal("slots were not returned on Close")
	}
}

func TestZeroLimitsReturnTheListenerUnchanged(t *testing.T) {
	inner, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer inner.Close()
	same, err := Listen(inner, Options{})
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	if same != inner {
		t.Fatal("zero limits should not wrap the listener")
	}
}

func TestNegativeLimitsAreRejected(t *testing.T) {
	inner, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer inner.Close()
	if _, err := Listen(inner, Options{MaxPerIP: -1}); err == nil {
		t.Fatal("negative per-IP limit was accepted")
	}
	if _, err := Listen(inner, Options{MaxTotal: -1}); err == nil {
		t.Fatal("negative total limit was accepted")
	}
	if _, err := Listen(nil, Options{MaxTotal: 1}); err == nil {
		t.Fatal("nil listener was accepted")
	}
}

func TestDoubleCloseReleasesSlotsOnce(t *testing.T) {
	inner, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer inner.Close()
	limited, err := Listen(inner, Options{MaxTotal: 4, MaxPerIP: 4})
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer limited.Close()
	accepted := make(chan net.Conn, 8)
	go func() {
		for {
			conn, err := limited.Accept()
			if err != nil {
				return
			}
			accepted <- conn
		}
	}()
	client, err := net.DialTimeout("tcp", inner.Addr().String(), 5*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer client.Close()
	select {
	case conn := <-accepted:
		_ = conn.Close()
		_ = conn.Close()
	case <-time.After(5 * time.Second):
		t.Fatal("connection was not accepted")
	}
	// MaxTotal is 4 and the first slot was returned once. Four concurrent
	// follow-ups must all be Accepted — a dial alone can succeed off the
	// kernel backlog after an immediate drop.
	var extras []net.Conn
	for i := 0; i < 4; i++ {
		extra, err := net.DialTimeout("tcp", inner.Addr().String(), 5*time.Second)
		if err != nil {
			t.Fatalf("dial %d: %v", i, err)
		}
		extras = append(extras, extra)
	}
	var held []net.Conn
	for i := 0; i < 4; i++ {
		select {
		case conn := <-accepted:
			held = append(held, conn)
		case <-time.After(5 * time.Second):
			t.Fatalf("follow-up %d was not accepted after double close", i)
		}
	}
	for _, conn := range held {
		_ = conn.Close()
	}
	for _, extra := range extras {
		_ = extra.Close()
	}
}

func TestCloseUnblocksAcceptWhenAtCapacity(t *testing.T) {
	inner, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	limited, err := Listen(inner, Options{MaxTotal: 1})
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	accepted := make(chan net.Conn, 1)
	secondErr := make(chan error, 1)
	go func() {
		conn, err := limited.Accept()
		if err != nil {
			secondErr <- err
			return
		}
		accepted <- conn
		_, err = limited.Accept()
		secondErr <- err
	}()
	client, err := net.DialTimeout("tcp", inner.Addr().String(), 5*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer client.Close()
	var held net.Conn
	select {
	case held = <-accepted:
	case err := <-secondErr:
		t.Fatalf("first Accept failed: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("first Accept timed out")
	}
	defer held.Close()
	time.Sleep(150 * time.Millisecond)
	closeDone := make(chan struct{})
	go func() {
		_ = limited.Close()
		close(closeDone)
	}()
	select {
	case <-closeDone:
	case <-time.After(2 * time.Second):
		t.Fatal("listener Close itself blocked")
	}
	select {
	case err := <-secondErr:
		if !errors.Is(err, net.ErrClosed) {
			t.Fatalf("second Accept after Close at capacity: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Accept still blocked after Close at MaxTotal capacity")
	}
}

func TestMaxTotalBoundsDistinctSources(t *testing.T) {
	inner, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	limited, err := Listen(inner, Options{MaxTotal: 2, MaxPerIP: 0})
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer limited.Close()
	accepted := make(chan net.Conn, 8)
	go func() {
		for {
			conn, err := limited.Accept()
			if err != nil {
				return
			}
			accepted <- conn
		}
	}()
	address := inner.Addr().String()
	var clients []net.Conn
	for i := 0; i < 2; i++ {
		c, err := net.DialTimeout("tcp", address, 5*time.Second)
		if err != nil {
			t.Fatalf("dial %d: %v", i, err)
		}
		clients = append(clients, c)
	}
	var held []net.Conn
	for i := 0; i < 2; i++ {
		select {
		case conn := <-accepted:
			held = append(held, conn)
		case <-time.After(5 * time.Second):
			t.Fatal("connections within MaxTotal were not accepted")
		}
	}
	third, err := net.DialTimeout("tcp", address, 500*time.Millisecond)
	if err == nil {
		clients = append(clients, third)
	}
	select {
	case conn := <-accepted:
		_ = conn.Close()
		t.Fatal("Accept took a connection above MaxTotal")
	case <-time.After(400 * time.Millisecond):
	}
	for _, c := range held {
		_ = c.Close()
	}
	for _, c := range clients {
		_ = c.Close()
	}
}

func TestDoubleCloseDoesNotFreeSiblingPerIPSlot(t *testing.T) {
	inner, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	limited, err := Listen(inner, Options{MaxTotal: 8, MaxPerIP: 2})
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer limited.Close()
	accepted := make(chan net.Conn, 8)
	go func() {
		for {
			conn, err := limited.Accept()
			if err != nil {
				return
			}
			accepted <- conn
		}
	}()
	address := inner.Addr().String()
	var clients []net.Conn
	for i := 0; i < 2; i++ {
		c, err := net.DialTimeout("tcp", address, 5*time.Second)
		if err != nil {
			t.Fatalf("dial %d: %v", i, err)
		}
		clients = append(clients, c)
	}
	var held []net.Conn
	for i := 0; i < 2; i++ {
		select {
		case conn := <-accepted:
			held = append(held, conn)
		case <-time.After(5 * time.Second):
			t.Fatal("two connections within cap were not accepted")
		}
	}
	_ = held[0].Close()
	_ = held[0].Close()
	third, err := net.DialTimeout("tcp", address, 5*time.Second)
	if err != nil {
		t.Fatalf("third dial: %v", err)
	}
	defer third.Close()
	select {
	case conn := <-accepted:
		held = append(held, conn)
	case <-time.After(5 * time.Second):
		t.Fatal("third connection within remaining cap was not accepted")
	}
	fourth, err := net.DialTimeout("tcp", address, 5*time.Second)
	if err != nil {
		t.Fatalf("fourth dial: %v", err)
	}
	defer fourth.Close()
	select {
	case conn := <-accepted:
		t.Errorf("double-close freed a sibling per-IP slot; fourth connection accepted")
		_ = conn.Close()
	case <-time.After(400 * time.Millisecond):
	}
	for _, c := range clients {
		_ = c.Close()
	}
	for _, c := range held[1:] {
		_ = c.Close()
	}
}
