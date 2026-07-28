package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/alexlafalce/ZTGotroller/internal/api/httpapi"
	"github.com/alexlafalce/ZTGotroller/internal/controller"
	sqlitestore "github.com/alexlafalce/ZTGotroller/internal/store/sqlite"
	"github.com/alexlafalce/ZTGotroller/internal/zerotier/identity"
	"github.com/alexlafalce/ZTGotroller/internal/zerotier/peer"
	"github.com/alexlafalce/ZTGotroller/internal/zerotier/transport"
)

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
	var (
		listenAddress = flag.String("listen", "127.0.0.1:9994", "administrative HTTP listen address")
		udpAddress    = flag.String("udp-listen", ":9993", "ZeroTier protocol UDP listen address")
		databasePath  = flag.String("database", "ztgotroller.db", "SQLite database path")
		identityPath  = flag.String("identity", "identity.secret", "controller identity secret path")
		upstreamsPath = flag.String("upstreams", "", "optional JSON file with upstream root identities and endpoints")
	)
	flag.Parse()

	controllerIdentity, created, err := identity.LoadOrCreate(context.Background(), *identityPath)
	if err != nil {
		return fmt.Errorf("controller identity: %w", err)
	}
	if created {
		log.Printf("generated controller identity %s", controllerIdentity.Address())
	}
	apiToken := os.Getenv("ZTGOTROLLER_API_TOKEN")
	if apiToken == "" {
		return errors.New("ZTGOTROLLER_API_TOKEN must be set")
	}
	persistence, err := sqlitestore.Open(*databasePath)
	if err != nil {
		return err
	}
	defer persistence.Close()

	service, err := controller.New(controllerIdentity.Address(), persistence, time.Now)
	if err != nil {
		return err
	}
	peerRegistry := peer.NewRegistry()
	handler, err := httpapi.RequireBearerToken(httpapi.NewWithPeers(service, peerRegistry), apiToken)
	if err != nil {
		return err
	}
	server := &http.Server{
		Addr:              *listenAddress,
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
	udpEndpoint, err := net.ResolveUDPAddr("udp", *udpAddress)
	if err != nil {
		return fmt.Errorf("resolve UDP listen address: %w", err)
	}
	udpConnection, err := net.ListenUDP("udp", udpEndpoint)
	if err != nil {
		return fmt.Errorf("listen UDP: %w", err)
	}
	defer udpConnection.Close()
	protocolHandler, err := transport.NewHandler(service, controllerIdentity, peerRegistry)
	if err != nil {
		return err
	}
	protocolServer, err := transport.NewUDPServer(udpConnection, protocolHandler)
	if err != nil {
		return err
	}
	var upstreamManager *transport.UpstreamManager
	if *upstreamsPath != "" {
		upstreams, err := transport.LoadUpstreams(*upstreamsPath)
		if err != nil {
			return fmt.Errorf("load upstreams: %w", err)
		}
		upstreamManager, err = transport.NewUpstreamManager(
			udpConnection, controllerIdentity, protocolHandler.Registry(), upstreams, 30*time.Second,
		)
		if err != nil {
			return err
		}
		protocolServer.SetUpstreamManager(upstreamManager)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	stopped := make(chan error, 2)
	go func() {
		log.Printf("administrative API listening on %s", server.Addr)
		err := server.ListenAndServe()
		if errors.Is(err, http.ErrServerClosed) {
			err = nil
		}
		stopped <- err
	}()
	if upstreamManager != nil {
		go func() {
			if err := upstreamManager.Run(ctx); err != nil {
				log.Printf("upstream announcements stopped: %v", err)
				stop()
			}
		}()
	}
	go func() {
		log.Printf("ZeroTier protocol listening on %s", udpConnection.LocalAddr())
		stopped <- protocolServer.Serve(ctx)
	}()

	workersRemaining := 2
	var result error
	select {
	case err := <-stopped:
		workersRemaining--
		result = err
		stop()
	case <-ctx.Done():
	}
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := server.Shutdown(shutdownCtx); err != nil && result == nil {
		result = fmt.Errorf("shutdown HTTP server: %w", err)
	}
	for workersRemaining > 0 {
		if err := <-stopped; err != nil && result == nil {
			result = err
		}
		workersRemaining--
	}
	return result
}
