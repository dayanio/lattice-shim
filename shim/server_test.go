// Copyright 2026 The Lattice Authors, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package shim_test

import (
	"context"
	"io"
	"net"
	"testing"
	"time"

	"github.com/alatticeio/lattice-shim/shim"
	"github.com/alatticeio/lattice-shim/shim/internal/test"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

func TestServer_PeerManagerDelegation(t *testing.T) {
	pm := &test.MockPeerManager{}

	srv, err := shim.NewServer("10.50.0.1", pm)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	defer srv.Close()

	var key [32]byte
	key[0] = 1
	_, subnet, _ := net.ParseCIDR("10.50.0.2/32")
	if err := srv.AddPeer(key, []net.IPNet{*subnet}, "1.2.3.4:51820"); err != nil {
		t.Fatalf("AddPeer: %v", err)
	}
	if !pm.HasPeer(key) {
		t.Error("expected peer to be added to MockPeerManager")
	}

	if err := srv.RemovePeer(key); err != nil {
		t.Fatalf("RemovePeer: %v", err)
	}
	if pm.HasPeer(key) {
		t.Error("expected peer to be removed from MockPeerManager")
	}
}

func TestServer_NilPeerManager(t *testing.T) {
	srv, err := shim.NewServer("10.50.0.1", nil)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	defer srv.Close()

	var key [32]byte
	_, subnet, _ := net.ParseCIDR("10.50.0.2/32")
	err = srv.AddPeer(key, []net.IPNet{*subnet}, "1.2.3.4:51820")
	if err == nil {
		t.Error("expected error when PeerManager is nil")
	}
}

// pumpPackets relays every outbound packet on `from` into `to` as an
// inbound packet, until ctx is canceled. It stands in for wireguard-go's
// encrypt/decrypt/deliver loop between two peers, which Server.Dial and
// Server.Listen do not need to know about.
func pumpPackets(ctx context.Context, from, to *channel.Endpoint) {
	for {
		pkt := from.ReadContext(ctx)
		if pkt == nil {
			return // ctx canceled
		}
		view := pkt.ToView()
		pkt.DecRef()
		if view == nil || view.Size() == 0 {
			continue
		}
		data := append([]byte(nil), view.AsSlice()...)
		relayView := buffer.NewViewWithData(data)
		var relayBuf buffer.Buffer
		_ = relayBuf.Append(relayView)
		relayPkt := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: relayBuf})
		to.InjectInbound(header.IPv4ProtocolNumber, relayPkt)
		relayPkt.DecRef()
	}
}

func TestServer_DialListen(t *testing.T) {
	a, err := shim.NewServer("10.50.0.1", &test.MockPeerManager{})
	if err != nil {
		t.Fatalf("NewServer(a): %v", err)
	}
	defer a.Close()

	b, err := shim.NewServer("10.50.0.2", &test.MockPeerManager{})
	if err != nil {
		t.Fatalf("NewServer(b): %v", err)
	}
	defer b.Close()

	pumpCtx, stopPump := context.WithCancel(context.Background())
	defer stopPump()
	go pumpPackets(pumpCtx, a.Channel(), b.Channel())
	go pumpPackets(pumpCtx, b.Channel(), a.Channel())

	ln, err := b.Listen("tcp", "10.50.0.2:9400")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer ln.Close()

	accepted := make(chan error, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			accepted <- err
			return
		}
		defer conn.Close()
		accepted <- nil
		io.Copy(conn, conn)
	}()

	dialCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	conn, err := a.Dial(dialCtx, "tcp", "10.50.0.2:9400")
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer conn.Close()

	select {
	case err := <-accepted:
		if err != nil {
			t.Fatalf("Accept: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for Accept")
	}

	msg := []byte("hello across two Server instances")
	if _, err := conn.Write(msg); err != nil {
		t.Fatalf("Write: %v", err)
	}
	buf := make([]byte, len(msg))
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("ReadFull: %v", err)
	}
	if string(buf) != string(msg) {
		t.Errorf("expected %q, got %q", msg, buf)
	}
}

func TestServer_ListenRejectsUDP(t *testing.T) {
	srv, err := shim.NewServer("10.50.0.1", nil)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	defer srv.Close()

	_, err = srv.Listen("udp", "10.50.0.1:9401")
	if err == nil {
		t.Error("expected error for unsupported network \"udp\"")
	}
}
