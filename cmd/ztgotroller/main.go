package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/alexlafalce/ZTGotroller/internal/api/httpapi"
	"github.com/alexlafalce/ZTGotroller/internal/controller"
	"github.com/alexlafalce/ZTGotroller/internal/domain"
	sqlitestore "github.com/alexlafalce/ZTGotroller/internal/store/sqlite"
)

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
	var (
		listenAddress = flag.String("listen", "127.0.0.1:9994", "administrative HTTP listen address")
		databasePath  = flag.String("database", "ztgotroller.db", "SQLite database path")
		controllerHex = flag.String("controller-id", "", "10-character ZeroTier controller node ID")
	)
	flag.Parse()

	controllerID, err := domain.ParseNodeID(*controllerHex)
	if err != nil {
		return fmt.Errorf("controller-id: %w", err)
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

	service, err := controller.New(controllerID, persistence, time.Now)
	if err != nil {
		return err
	}
	handler, err := httpapi.RequireBearerToken(httpapi.New(service), apiToken)
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

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	stopped := make(chan error, 1)
	go func() {
		log.Printf("administrative API listening on %s", server.Addr)
		err := server.ListenAndServe()
		if errors.Is(err, http.ErrServerClosed) {
			err = nil
		}
		stopped <- err
	}()

	select {
	case err := <-stopped:
		return err
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := server.Shutdown(shutdownCtx); err != nil {
			return fmt.Errorf("shutdown HTTP server: %w", err)
		}
		return <-stopped
	}
}
