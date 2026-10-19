// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build tailcat_close_stress

package tailcat

import (
	"context"
	"io"
	"net"
	"testing"
	"time"

	"tailscale.com/tstest/integration"
	"tailscale.com/types/key"
	"tailscale.com/wgengine/filter"
)

// TestCloseAfter550ShortTCPSessions151 is a manual regression probe for
// tailscale/tailcat#151. Run in its own test process with
// go test -tags=tailcat_close_stress -run TestCloseAfter550ShortTCPSessions151.
// It intentionally does not run in the regular suite: the vulnerable
// dependency can leave Server.Close blocked indefinitely.
func TestCloseAfter550ShortTCPSessions151(t *testing.T) {
	const count = 550
	dm := integration.RunDERPAndSTUN(t, mkLogger(t, "derpstun"), "127.0.0.1")
	reg := dm.Regions[1]
	if reg == nil {
		t.Fatal("missing test DERP region")
	}
	clientKey := key.NewNode()
	s := &Server{
		Logf:           mkLogger(t, "server"),
		Region:         reg,
		AllowClient:    func(k key.NodePublic) bool { return k == clientKey.Public() },
		ServedTCPPorts: []filter.PortRange{{First: 80, Last: 80}},
		OnTCP: func(port uint16) func(net.Conn) {
			if port != 80 {
				return nil
			}
			return func(conn net.Conn) {
				defer conn.Close() // Server initiates close before the client reads EOF.
				conn.SetDeadline(time.Now().Add(8 * time.Second))
				_, _ = io.WriteString(conn, "x")
			}
		},
	}
	if err := s.Start(); err != nil {
		t.Fatal(err)
	}
	c := &Client{Server: s.TailcatAddr(), Key: clientKey, Logf: mkLogger(t, "client")}
	PingForTest(t, s, c)
	totalStart := time.Now()
	overall, cancel := context.WithTimeout(context.Background(), 65*time.Second)
	defer cancel()
	for i := 0; i < count; i++ {
		if err := overall.Err(); err != nil {
			t.Fatalf("establishing %d/%d connections: %v", i, count, err)
		}
		var conn net.Conn
		var err error
		for attempt := 0; attempt < 12; attempt++ {
			ctx, stop := context.WithTimeout(overall, 500*time.Millisecond)
			conn, err = c.DialTCPPort(ctx, 80)
			stop()
			if err == nil {
				break
			}
			// Transient dials can stall (potentially because of TIME_WAIT
			// 4-tuple reuse); bound retries rather than treating a stall
			// as evidence of the shutdown regression.
		}
		if err != nil {
			t.Fatalf("dial #%d exhausted 12 bounded retries: %v", i, err)
		}
		conn.SetDeadline(time.Now().Add(3 * time.Second))
		b, err := io.ReadAll(conn)
		conn.Close()
		if err != nil || string(b) != "x" {
			t.Fatalf("read #%d = %q, %v; want x and EOF", i, b, err)
		}
		// Reading to EOF confirms the server closed this connection.
	}
	t.Logf("Completed %d server-first short sessions in %s; attempting Server.Close", count, time.Since(totalStart))
	closeResult := make(chan error, 1)
	go func() { closeResult <- s.Close() }()
	select {
	case err := <-closeResult:
		if err != nil {
			t.Fatal(err)
		}
		t.Logf("Server.Close returned after %d sessions in %s", count, time.Since(totalStart))
	case <-time.After(5 * time.Second):
		// No cleanup that might block: this is a dedicated one-off test process.
		t.Fatalf("Server.Close stuck after %d sessions; old dependency regression likely", count)
	}
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
}
