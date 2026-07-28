package transport

import (
	"context"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/alexlafalce/ZTGotroller/internal/controller"
	"github.com/alexlafalce/ZTGotroller/internal/domain"
	"github.com/alexlafalce/ZTGotroller/internal/store/memory"
	"github.com/alexlafalce/ZTGotroller/internal/zerotier/identity"
	"github.com/alexlafalce/ZTGotroller/internal/zerotier/networkconfig"
	"github.com/alexlafalce/ZTGotroller/internal/zerotier/packet"
	"github.com/alexlafalce/ZTGotroller/internal/zerotier/peer"
)

func TestUDPServerEndToEnd(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	controllerIdentity := transportController(t)
	remoteIdentity, err := identity.Generate(
		ctx,
		newRepeatingReader(0x77),
	)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_700_000_000, 0).UTC()
	service, err := controller.New(controllerIdentity.Address(), memory.New(), func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	network, err := service.CreateNetwork(ctx, 1, "socket-test")
	if err != nil {
		t.Fatal(err)
	}
	handler, err := NewHandler(service, controllerIdentity, peer.NewRegistry())
	if err != nil {
		t.Fatal(err)
	}
	handler.now = func() time.Time { return now }
	serverConnection, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	server, err := NewUDPServer(serverConnection, handler)
	if err != nil {
		t.Fatal(err)
	}
	stopped := make(chan error, 1)
	go func() { stopped <- server.Serve(ctx) }()

	client, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	serverEndpoint := serverConnection.LocalAddr().(*net.UDPAddr).AddrPort()
	clientReassembler := newReassembler()
	hello, key := buildHelloDatagram(t, controllerIdentity, remoteIdentity, false)
	writeUDP(t, client, serverEndpoint, hello)
	reply := readPacketUDP(t, client, serverEndpoint, clientReassembler)
	if decoded, err := packet.DearmorSession(reply, key); err != nil || decoded.Verb != packet.VerbOK {
		t.Fatalf("invalid socket HELLO reply: %+v, %v", decoded, err)
	}

	request := buildConfigDatagram(t, controllerIdentity, remoteIdentity, network.ID, key, 2)
	writeUDP(t, client, serverEndpoint, request)
	denial := readPacketUDP(t, client, serverEndpoint, clientReassembler)
	if decoded, err := packet.DearmorSession(denial, key); err != nil || decoded.Verb != packet.VerbError {
		t.Fatalf("invalid socket denial: %+v, %v", decoded, err)
	}

	network, err = service.UpdateNetwork(ctx, network.ID, controller.NetworkUpdate{
		Name:            network.Name,
		Private:         true,
		MTU:             domain.DefaultMTU,
		MulticastLimit:  domain.DefaultMulticastLimit,
		EnableBroadcast: true,
		Routes:          []domain.Route{{Target: netip.MustParsePrefix("10.77.0.0/16")}},
		Rules:           []domain.Rule{{Type: "ACTION_ACCEPT"}},
	}, network.Revision)
	if err != nil {
		t.Fatal(err)
	}
	member, err := service.GetMember(ctx, network.ID, remoteIdentity.Address())
	if err != nil {
		t.Fatal(err)
	}
	member, err = service.UpdateMember(ctx, network.ID, member.NodeID, controller.MemberUpdate{
		IPAssignments: []netip.Addr{netip.MustParseAddr("10.77.0.2")},
	}, member.Revision)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.SetMemberAuthorization(
		ctx, network.ID, member.NodeID, true, member.Revision,
	); err != nil {
		t.Fatal(err)
	}
	writeUDP(t, client, serverEndpoint, request)
	configReply := readPacketUDP(t, client, serverEndpoint, clientReassembler)
	decodedConfig, err := packet.DearmorSession(configReply, key)
	if err != nil {
		t.Fatal(err)
	}
	if decodedConfig.Verb != packet.VerbOK {
		t.Fatalf("config response verb = %d", decodedConfig.Verb)
	}
	chunk, err := networkconfig.ParseSignedChunk(
		decodedConfig.Payload[9:], controllerIdentity.Public(),
	)
	if err != nil {
		t.Fatal(err)
	}
	dictionary, err := networkconfig.ParseMetadata(chunk.Data)
	if err != nil {
		t.Fatal(err)
	}
	if len(dictionary["C"]) == 0 || len(dictionary["COO"]) == 0 || len(dictionary["I"]) == 0 {
		t.Fatal("socket configuration lacks COM, COO, or assigned IP")
	}

	cancel()
	if err := <-stopped; err != nil {
		t.Fatal(err)
	}
}

func writeUDP(t *testing.T, connection *net.UDPConn, endpoint netip.AddrPort, payload []byte) {
	t.Helper()
	if _, err := connection.WriteToUDPAddrPort(payload, endpoint); err != nil {
		t.Fatal(err)
	}
}

func readUDP(t *testing.T, connection *net.UDPConn) []byte {
	t.Helper()
	if err := connection.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, packet.MaxPacketLength)
	length, _, err := connection.ReadFromUDPAddrPort(buffer)
	if err != nil {
		t.Fatal(err)
	}
	return append([]byte(nil), buffer[:length]...)
}

func readPacketUDP(
	t *testing.T,
	connection *net.UDPConn,
	endpoint netip.AddrPort,
	reassembler *reassembler,
) []byte {
	t.Helper()
	for count := 0; count < packet.MaxPacketFragments; count++ {
		datagram := readUDP(t, connection)
		assembled, ready, err := reassembler.push(datagram, endpoint, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		if ready {
			return assembled
		}
	}
	t.Fatal("packet did not complete within maximum fragment count")
	return nil
}

type repeatingReader byte

func newRepeatingReader(value byte) repeatingReader {
	return repeatingReader(value)
}

func (reader repeatingReader) Read(buffer []byte) (int, error) {
	for index := range buffer {
		buffer[index] = byte(reader)
	}
	return len(buffer), nil
}
