package httpapi

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/alexlafalce/ZTGotroller/internal/controller"
	"github.com/alexlafalce/ZTGotroller/internal/domain"
	"github.com/alexlafalce/ZTGotroller/internal/store/memory"
)

func TestAdministrativeLifecycle(t *testing.T) {
	api := newTestAPI(t)

	networkResponse := perform(t, api, http.MethodPost, "/v1/networks", `{
		"sequence": 7,
		"name": "home"
	}`)
	if networkResponse.Code != http.StatusCreated {
		t.Fatalf("create network returned %d: %s", networkResponse.Code, networkResponse.Body.String())
	}
	var network domain.Network
	decodeResponse(t, networkResponse, &network)

	memberPath := "/v1/networks/" + string(network.ID) + "/members/abcdef1234"
	memberResponse := perform(t, api, http.MethodPost, memberPath, "")
	if memberResponse.Code != http.StatusOK {
		t.Fatalf("register member returned %d: %s", memberResponse.Code, memberResponse.Body.String())
	}
	var member domain.Member
	decodeResponse(t, memberResponse, &member)

	authorizationResponse := perform(
		t,
		api,
		http.MethodPut,
		memberPath+"/authorization",
		`{"authorized":true,"revision":1}`,
	)
	if authorizationResponse.Code != http.StatusOK {
		t.Fatalf(
			"authorize member returned %d: %s",
			authorizationResponse.Code,
			authorizationResponse.Body.String(),
		)
	}
	decodeResponse(t, authorizationResponse, &member)
	if !member.Authorized || member.Revision != 2 {
		t.Fatalf("unexpected authorized member: %+v", member)
	}
}

func TestConflictAndInvalidInputResponses(t *testing.T) {
	api := newTestAPI(t)
	perform(t, api, http.MethodPost, "/v1/networks", `{"sequence":1,"name":"test"}`)
	memberPath := "/v1/networks/8056c2e21c000001/members/abcdef1234"
	perform(t, api, http.MethodPost, memberPath, "")

	conflict := perform(
		t, api, http.MethodPut, memberPath+"/authorization",
		`{"authorized":true,"revision":0}`,
	)
	if conflict.Code != http.StatusConflict {
		t.Fatalf("got status %d, want 409", conflict.Code)
	}

	invalid := perform(t, api, http.MethodPost, "/v1/networks", `{"unknown":true}`)
	if invalid.Code != http.StatusBadRequest {
		t.Fatalf("got status %d, want 400", invalid.Code)
	}
}

func newTestAPI(t *testing.T) http.Handler {
	t.Helper()
	service, err := controller.New(
		"8056c2e21c",
		memory.New(),
		func() time.Time { return time.Date(2026, 7, 27, 12, 0, 0, 0, time.UTC) },
	)
	if err != nil {
		t.Fatal(err)
	}
	return New(service)
}

func perform(t *testing.T, handler http.Handler, method, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	request := httptest.NewRequest(method, path, bytes.NewBufferString(body))
	if body != "" {
		request.Header.Set("Content-Type", "application/json")
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	return response
}

func decodeResponse(t *testing.T, response *httptest.ResponseRecorder, destination any) {
	t.Helper()
	if err := json.NewDecoder(response.Body).Decode(destination); err != nil {
		t.Fatal(err)
	}
}
