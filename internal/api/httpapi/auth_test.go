package httpapi

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestBearerAuthentication(t *testing.T) {
	protected, err := RequireBearerToken(newTestAPI(t), "correct-token")
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name   string
		path   string
		header string
		status int
	}{
		{name: "missing", path: "/v1/networks", status: http.StatusUnauthorized},
		{name: "wrong", path: "/v1/networks", header: "Bearer wrong", status: http.StatusUnauthorized},
		{name: "valid", path: "/v1/networks", header: "Bearer correct-token", status: http.StatusOK},
		{name: "health", path: "/healthz", status: http.StatusOK},
	} {
		t.Run(test.name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodGet, test.path, nil)
			request.Header.Set("Authorization", test.header)
			response := httptest.NewRecorder()
			protected.ServeHTTP(response, request)
			if response.Code != test.status {
				t.Fatalf("got status %d, want %d", response.Code, test.status)
			}
		})
	}
}

func TestBearerAuthenticationRequiresConfiguration(t *testing.T) {
	if _, err := RequireBearerToken(newTestAPI(t), ""); err == nil {
		t.Fatal("expected empty token to be rejected")
	}
}
