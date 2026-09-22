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
	"net"
	"testing"

	"github.com/alatticeio/lattice-shim/shim"
	"github.com/alatticeio/lattice-shim/shim/internal/test"
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
