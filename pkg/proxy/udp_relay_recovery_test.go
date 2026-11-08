package proxy

import (
	"fmt"
	"net"
	"runtime"
	"testing"
	"time"
)

func waitUDPRelaySessionCount(t *testing.T, relay *UDPRelay, want int) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if relay.SessionCount() == want {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("session count = %d, want %d", relay.SessionCount(), want)
}

func udpRelayRecoveryFixture(t *testing.T) (*UDPRelay, *net.UDPConn, *net.UDPConn, int) {
	t.Helper()
	backend, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = backend.Close() })
	port := freeUDPPort(t)
	relay := NewUDPRelay("recovery-test", "127.0.0.1", "127.0.0.1", []int{port})
	relay.backendPorts = map[int]int{port: backend.LocalAddr().(*net.UDPAddr).Port}
	if failures := relay.Start(); len(failures) != 0 {
		t.Fatal(failures)
	}
	t.Cleanup(relay.Stop)
	client, err := net.DialUDP("udp4", nil, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: port})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	return relay, backend, client, port
}

func udpRelayRecoveryRound(t *testing.T, backend, client *net.UDPConn, label string) {
	t.Helper()
	if _, err := client.Write([]byte(label)); err != nil {
		t.Fatal(err)
	}
	request, source := readWithTimeout(t, backend, "backend")
	if string(request) != label {
		t.Fatalf("request = %q, want %q", request, label)
	}
	if _, err := backend.WriteToUDP([]byte("reply-"+label), source); err != nil {
		t.Fatal(err)
	}
	reply, _ := readWithTimeout(t, client, "client")
	if string(reply) != "reply-"+label {
		t.Fatalf("reply = %q, want reply-%s", reply, label)
	}
}

func TestUDPRelayReadFailureRetiresSession(t *testing.T) {
	relay, backend, client, port := udpRelayRecoveryFixture(t)
	udpRelayRecoveryRound(t, backend, client, "first")
	address := client.LocalAddr().(*net.UDPAddr)
	old := relay.sessionFor(port, address)
	// A read error must retire the map entry even if no future write fails.
	_ = old.upstream.Close()
	waitUDPRelaySessionCount(t, relay, 0)
	udpRelayRecoveryRound(t, backend, client, "second")
	if relay.sessionFor(port, address) == old {
		t.Fatal("reused the session whose return reader already exited")
	}
}

func TestUDPRelayBackendCloseReopenAcrossRounds(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("requires Linux connected UDP ICMP error delivery")
	}
	relay, backend, client, _ := udpRelayRecoveryFixture(t)
	address := backend.LocalAddr().(*net.UDPAddr)
	for round := 0; round < 3; round++ {
		udpRelayRecoveryRound(t, backend, client, fmt.Sprintf("round-%d", round))
		if err := backend.Close(); err != nil {
			t.Fatal(err)
		}
		// Late traffic reaches a retired dungeon port and causes ECONNREFUSED.
		if _, err := client.Write([]byte("late-packet")); err != nil {
			t.Fatal(err)
		}
		waitUDPRelaySessionCount(t, relay, 0)
		var err error
		backend, err = net.ListenUDP("udp4", address)
		if err != nil {
			t.Fatal(err)
		}
		current := backend
		t.Cleanup(func() { _ = current.Close() })
	}
	udpRelayRecoveryRound(t, backend, client, "final")
}

func TestUDPRelayOldCleanupPreservesReplacement(t *testing.T) {
	relay, backend, client, port := udpRelayRecoveryFixture(t)
	address := client.LocalAddr().(*net.UDPAddr)
	old := relay.sessionFor(port, address)
	relay.dropSession(port, old)
	replacement := relay.sessionFor(port, address)
	if replacement == old {
		t.Fatal("replacement reused the old socket")
	}
	// Model a delayed old reader or writer after an idle sweep/replacement.
	relay.dropSession(port, old)
	if relay.SessionCount() != 1 || relay.sessionFor(port, address) != replacement {
		t.Fatal("old cleanup removed the replacement")
	}
	udpRelayRecoveryRound(t, backend, client, "replacement")
}

func TestUDPRelayStopConcurrentWithReaderCleanup(t *testing.T) {
	relay, _, client, port := udpRelayRecoveryFixture(t)
	address := client.LocalAddr().(*net.UDPAddr)
	session := relay.sessionFor(port, address)
	done := make(chan struct{})
	go func() {
		relay.dropSession(port, session)
		close(done)
	}()
	relay.Stop()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("cleanup blocked during Stop")
	}
	if relay.SessionCount() != 0 || relay.sessionFor(port, address) != nil {
		t.Fatal("stopped relay retained or created a session")
	}
}
