package transport

import (
	"context"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/alexlafalce/ZTGotroller/internal/zerotier/identity"
	"github.com/alexlafalce/ZTGotroller/internal/zerotier/packet"
	"github.com/alexlafalce/ZTGotroller/internal/zerotier/peer"
)

func TestUpstreamAnnouncementRoundTrip(t *testing.T) {
	ctx := context.Background()
	controllerIdentity := transportController(t)
	rootIdentity, err := identity.Generate(ctx, newRepeatingReader(0x31))
	if err != nil {
		t.Fatal(err)
	}
	rootSocket, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer rootSocket.Close()
	controllerSocket, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer controllerSocket.Close()

	registry := peer.NewRegistry()
	manager, err := NewUpstreamManager(
		controllerSocket, controllerIdentity, registry,
		[]Upstream{{
			Identity:  rootIdentity.Public(),
			Endpoints: []netip.AddrPort{rootSocket.LocalAddr().(*net.UDPAddr).AddrPort()},
		}},
		time.Minute,
	)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_700_000_000, 0).UTC()
	manager.now = func() time.Time { return now }
	manager.random = newRepeatingReader(0x52)
	if err := manager.announce(); err != nil {
		t.Fatal(err)
	}
	status := manager.Status()
	if len(status) != 1 || !status[0].Pending || !status[0].LastAttempt.Equal(now) {
		t.Fatalf("unexpected pending upstream status: %+v", status)
	}

	buffer := make([]byte, packet.MaxPacketLength)
	if err := rootSocket.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	length, remote, err := rootSocket.ReadFromUDPAddrPort(buffer)
	if err != nil {
		t.Fatal(err)
	}
	hello, key, err := packet.AuthenticateHello(buffer[:length], rootIdentity)
	if err != nil {
		t.Fatal(err)
	}
	reply, err := packet.BuildHelloOK(
		900, hello, rootIdentity,
		packet.InetAddress{Address: remote.Addr(), Port: remote.Port()},
		packet.LocalVersion{Protocol: packet.ProtocolVersionCurrent, Major: 1, Minor: 14, Revision: 2},
		key,
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := rootSocket.WriteToUDPAddrPort(reply, remote); err != nil {
		t.Fatal(err)
	}
	if err := controllerSocket.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	length, responseRemote, err := controllerSocket.ReadFromUDPAddrPort(buffer)
	if err != nil {
		t.Fatal(err)
	}
	handled, err := manager.Handle(buffer[:length], responseRemote)
	if err != nil {
		t.Fatal(err)
	}
	if !handled {
		t.Fatal("valid HELLO OK was not consumed")
	}
	status = manager.Status()
	if len(status) != 1 || status[0].Pending || !status[0].LastSuccess.Equal(now) {
		t.Fatalf("unexpected successful upstream status: %+v", status)
	}
}

func TestLoadUpstreams(t *testing.T) {
	rootIdentity, err := identity.Generate(context.Background(), newRepeatingReader(0x61))
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "upstreams.json")
	content := `{"upstreams":[{"identity":"` + rootIdentity.Public().String() +
		`","endpoints":["192.0.2.1:9993","[2001:db8::1]:9993"]}]}`
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	upstreams, err := LoadUpstreams(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(upstreams) != 1 || len(upstreams[0].Endpoints) != 2 ||
		upstreams[0].Identity.Address() != rootIdentity.Address() {
		t.Fatalf("unexpected upstreams: %+v", upstreams)
	}
}
