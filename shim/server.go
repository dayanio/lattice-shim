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

package shim

import (
	"context"
	"fmt"
	"net"

	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
)

// Server is a tsnet-style embeddable network node: a Netstack plus a
// PeerManager, exposing Dial and Listen directly. Unlike Sandbox, Server
// does not wire up a SOCKS5 proxy or ForwardListener relay — callers get
// raw net.Conn/net.Listener values backed by the user-space netstack.
//
// Server is intended for embedding overlay connectivity into a host
// process that does not want (or cannot get) a kernel TUN device — for
// example a mobile app extension with no elevated network privilege.
type Server struct {
	ns    *Netstack
	peers PeerManager
}

// NewServer creates a Server bound to overlayIP. pm is the PeerManager
// that will receive AddPeer/RemovePeer calls; it may be nil, in which case
// AddPeer/RemovePeer return an error (mirroring Sandbox's behavior with no
// PeerManager configured). opts configures the underlying Netstack (e.g.
// WithIdentity, WithPolicy, WithAudit).
func NewServer(overlayIP string, pm PeerManager, opts ...NetstackOption) (*Server, error) {
	ns, err := NewNetstack(overlayIP, opts...)
	if err != nil {
		return nil, fmt.Errorf("netstack: %w", err)
	}
	return &Server{ns: ns, peers: pm}, nil
}

// AddPeer delegates to the injected PeerManager.
// Returns an error if no PeerManager was configured.
func (s *Server) AddPeer(pubKey [32]byte, allowedIPs []net.IPNet, endpoint string) error {
	if s.peers == nil {
		return fmt.Errorf("server: no PeerManager configured")
	}
	return s.peers.AddPeer(pubKey, allowedIPs, endpoint)
}

// RemovePeer delegates to the injected PeerManager.
// Returns an error if no PeerManager was configured.
func (s *Server) RemovePeer(pubKey [32]byte) error {
	if s.peers == nil {
		return fmt.Errorf("server: no PeerManager configured")
	}
	return s.peers.RemovePeer(pubKey)
}

// Dial dials a remote address through the user-space netstack. See
// Netstack.DialContext for supported network values ("tcp", "tcp4",
// "udp", "udp4").
func (s *Server) Dial(ctx context.Context, network, addr string) (net.Conn, error) {
	return s.ns.DialContext(ctx, network, addr)
}

// Listen creates a TCP listener on the netstack at addr. network must be
// "tcp" or "tcp4".
func (s *Server) Listen(network, addr string) (net.Listener, error) {
	switch network {
	case "tcp", "tcp4":
		return s.ns.ListenTCP(addr)
	default:
		return nil, fmt.Errorf("unsupported network: %s", network)
	}
}

// Channel returns the channel endpoint for wireguard-go attachment — the
// caller's WireGuard bridge (e.g. a tun.Device adapter) reads outbound
// packets from and injects inbound packets into this endpoint.
func (s *Server) Channel() *channel.Endpoint { return s.ns.Channel() }

// Close destroys the underlying netstack.
func (s *Server) Close() error {
	return s.ns.Close()
}
