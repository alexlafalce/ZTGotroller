package transport

import (
	"context"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/alexlafalce/ZTGotroller/internal/zerotier/packet"
)

type UDPServer struct {
	connection *net.UDPConn
	handler    *Handler
	fragments  *reassembler
	upstream   *UpstreamManager
}

func (server *UDPServer) SetUpstreamManager(manager *UpstreamManager) {
	server.upstream = manager
}

func NewUDPServer(connection *net.UDPConn, handler *Handler) (*UDPServer, error) {
	if connection == nil || handler == nil {
		return nil, errors.New("UDP connection and handler are required")
	}
	return &UDPServer{
		connection: connection,
		handler:    handler,
		fragments:  newReassembler(),
	}, nil
}

func (server *UDPServer) Serve(ctx context.Context) error {
	stop := context.AfterFunc(ctx, func() { _ = server.connection.Close() })
	defer stop()
	buffer := make([]byte, packet.MaxPacketLength)
	for {
		length, remote, err := server.connection.ReadFromUDPAddrPort(buffer)
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return nil
			}
			return fmt.Errorf("read UDP: %w", err)
		}
		datagram, ready, err := server.fragments.push(buffer[:length], remote, time.Now())
		if err != nil || !ready {
			continue
		}
		if server.upstream != nil {
			handled, err := server.upstream.Handle(datagram, remote)
			if handled {
				continue
			}
			if err != nil {
				continue
			}
		}
		replies, err := server.handler.Handle(ctx, datagram, remote)
		if err != nil {
			continue // invalid/untrusted datagrams are intentionally silent
		}
		for _, reply := range replies {
			if _, err := server.connection.WriteToUDPAddrPort(reply, remote); err != nil {
				if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
					return nil
				}
				return fmt.Errorf("write UDP: %w", err)
			}
		}
	}
}
