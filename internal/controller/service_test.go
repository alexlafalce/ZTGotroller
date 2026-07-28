package controller

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/alexlafalce/ZTGotroller/internal/domain"
	"github.com/alexlafalce/ZTGotroller/internal/store"
	"github.com/alexlafalce/ZTGotroller/internal/store/memory"
)

func TestNetworkAndMemberAuthorizationLifecycle(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 7, 27, 12, 0, 0, 0, time.UTC)
	service := newTestService(t, func() time.Time { return now })

	network, err := service.CreateNetwork(ctx, 42, "home")
	if err != nil {
		t.Fatal(err)
	}
	if network.ID != "8056c2e21c00002a" || network.Revision != 1 {
		t.Fatalf("unexpected network: %+v", network)
	}

	member, err := service.RegisterMember(ctx, network.ID, "abcdef1234")
	if err != nil {
		t.Fatal(err)
	}
	if member.Authorized || member.Revision != 1 {
		t.Fatalf("new member must be unauthorized at revision 1: %+v", member)
	}

	now = now.Add(time.Minute)
	authorized, err := service.SetMemberAuthorization(
		ctx, network.ID, member.NodeID, true, member.Revision,
	)
	if err != nil {
		t.Fatal(err)
	}
	if !authorized.Authorized || authorized.Revision != 2 || !authorized.UpdatedAt.Equal(now) {
		t.Fatalf("unexpected authorized member: %+v", authorized)
	}
}

func TestRegisterMemberIsIdempotent(t *testing.T) {
	ctx := context.Background()
	service := newTestService(t, time.Now)
	network, err := service.CreateNetwork(ctx, 1, "test")
	if err != nil {
		t.Fatal(err)
	}
	first, err := service.RegisterMember(ctx, network.ID, "abcdef1234")
	if err != nil {
		t.Fatal(err)
	}
	second, err := service.RegisterMember(ctx, network.ID, "abcdef1234")
	if err != nil {
		t.Fatal(err)
	}
	if first.Revision != second.Revision || first.NodeID != second.NodeID {
		t.Fatalf("idempotent registration changed member: %+v != %+v", first, second)
	}
}

func TestAuthorizationRejectsStaleRevision(t *testing.T) {
	ctx := context.Background()
	service := newTestService(t, time.Now)
	network, err := service.CreateNetwork(ctx, 1, "test")
	if err != nil {
		t.Fatal(err)
	}
	member, err := service.RegisterMember(ctx, network.ID, "abcdef1234")
	if err != nil {
		t.Fatal(err)
	}
	_, err = service.SetMemberAuthorization(ctx, network.ID, member.NodeID, true, 0)
	if !errors.Is(err, store.ErrConflict) {
		t.Fatalf("got %v, want revision conflict", err)
	}
}

func TestDeauthorizationPublishesRevocationEvent(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 7, 28, 12, 0, 0, 0, time.UTC)
	service := newTestService(t, func() time.Time { return now })
	network, err := service.CreateNetwork(ctx, 1, "test")
	if err != nil {
		t.Fatal(err)
	}
	member, err := service.RegisterMember(ctx, network.ID, "abcdef1234")
	if err != nil {
		t.Fatal(err)
	}
	member, err = service.SetMemberAuthorization(ctx, network.ID, member.NodeID, true, member.Revision)
	if err != nil {
		t.Fatal(err)
	}
	called := false
	service.SetDeauthorizationHandler(func(
		_ context.Context, gotNetwork domain.NetworkID, gotNode domain.NodeID, threshold time.Time,
	) {
		called = gotNetwork == network.ID && gotNode == member.NodeID && threshold.Equal(now)
	})
	if _, err := service.SetMemberAuthorization(
		ctx, network.ID, member.NodeID, false, member.Revision,
	); err != nil {
		t.Fatal(err)
	}
	if !called {
		t.Fatal("deauthorization event was not published")
	}
}

func TestRejectsForeignControllerNetwork(t *testing.T) {
	service := newTestService(t, time.Now)
	_, err := service.RegisterMember(context.Background(), "1122334455000001", "abcdef1234")
	if err == nil {
		t.Fatal("expected foreign controller network to be rejected")
	}
}

func TestCreateNetworkRejectsSequenceOverflow(t *testing.T) {
	service := newTestService(t, time.Now)
	_, err := service.CreateNetwork(context.Background(), 0x01000000, "invalid")
	if err == nil {
		t.Fatal("expected sequence overflow error")
	}
}

func newTestService(t *testing.T, clock Clock) *Service {
	t.Helper()
	controllerID := domain.NodeID("8056c2e21c")
	service, err := New(controllerID, memory.New(), clock)
	if err != nil {
		t.Fatal(err)
	}
	return service
}
