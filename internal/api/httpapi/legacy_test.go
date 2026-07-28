package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"
	"time"

	"github.com/alexlafalce/ZTGotroller/internal/controller"
	"github.com/alexlafalce/ZTGotroller/internal/store/memory"
	"github.com/alexlafalce/ZTGotroller/internal/zerotier/identity"
	"github.com/alexlafalce/ZTGotroller/internal/zerotier/packet"
	"github.com/alexlafalce/ZTGotroller/internal/zerotier/peer"
)

func TestLegacyControllerLifecycle(t *testing.T) {
	api := newTestAPI(t)
	status := perform(t, api, http.MethodGet, "/status", "")
	var statusBody map[string]any
	decodeResponse(t, status, &statusBody)
	if status.Code != http.StatusOK || statusBody["address"] != "8056c2e21c" {
		t.Fatalf("unexpected status (%d): %#v", status.Code, statusBody)
	}

	created := perform(t, api, http.MethodPost, "/controller/network/8056c2e21c______", `{
		"name":"legacy","private":true,"enableBroadcast":true,"mtu":2800,
		"multicastLimit":32,"v4AssignMode":{"zt":true},
		"routes":[{"target":"10.44.0.0/16","via":null}],
		"ipAssignmentPools":[{"ipRangeStart":"10.44.0.10","ipRangeEnd":"10.44.0.200"}],
		"dns":{"domain":"home.arpa","servers":["10.44.0.1"]},
		"rules":[{"type":"ACTION_ACCEPT","not":false,"or":false}],
		"capabilities":[{"id":1,"default":true,"rules":[{"type":"ACTION_ACCEPT"}]}],
		"tags":[{"id":7,"default":3}]
	}`)
	if created.Code != http.StatusOK {
		t.Fatalf("create returned %d: %s", created.Code, created.Body.String())
	}
	var network map[string]any
	decodeResponse(t, created, &network)
	nwid, ok := network["nwid"].(string)
	if !ok || len(nwid) != 16 || nwid[:10] != "8056c2e21c" {
		t.Fatalf("unexpected network ID: %#v", network["nwid"])
	}
	if network["revision"] != float64(1) {
		t.Fatalf("new network revision = %#v, want 1", network["revision"])
	}

	list := perform(t, api, http.MethodGet, "/controller/network", "")
	var ids []string
	decodeResponse(t, list, &ids)
	if len(ids) != 1 || ids[0] != nwid {
		t.Fatalf("unexpected network list: %#v", ids)
	}

	memberPath := "/controller/network/" + nwid + "/member/abcdef1234"
	memberResponse := perform(t, api, http.MethodPost, memberPath, `{
		"name":"router","authorized":true,"noAutoAssignIps":true,
		"ipAssignments":["10.44.0.20"],"capabilities":[1,1],"tags":[[7,9]]
	}`)
	if memberResponse.Code != http.StatusOK {
		t.Fatalf("member update returned %d: %s", memberResponse.Code, memberResponse.Body.String())
	}
	var member map[string]any
	decodeResponse(t, memberResponse, &member)
	if member["authorized"] != true || member["name"] != "router" {
		t.Fatalf("unexpected member: %#v", member)
	}

	memberList := perform(t, api, http.MethodGet, "/controller/network/"+nwid+"/member", "")
	var revisions map[string]uint64
	decodeResponse(t, memberList, &revisions)
	if revisions["abcdef1234"] == 0 {
		t.Fatalf("unexpected member list: %#v", revisions)
	}

	partial := perform(t, api, http.MethodPost, "/controller/network/"+nwid, `{"name":"renamed"}`)
	var updated map[string]json.RawMessage
	decodeResponse(t, partial, &updated)
	var routes []legacyRoute
	if partial.Code != http.StatusOK || json.Unmarshal(updated["routes"], &routes) != nil || len(routes) != 1 {
		t.Fatalf("partial update lost routes: %s", partial.Body.String())
	}

	if response := perform(t, api, http.MethodDelete, memberPath, ""); response.Code != http.StatusOK {
		t.Fatalf("delete member returned %d: %s", response.Code, response.Body.String())
	}
	if response := perform(t, api, http.MethodDelete, "/controller/network/"+nwid, ""); response.Code != http.StatusOK {
		t.Fatalf("delete network returned %d: %s", response.Code, response.Body.String())
	}
}

func TestLegacyControllerReportsBaselineAPIVersion(t *testing.T) {
	response := perform(t, newTestAPI(t), http.MethodGet, "/controller", "")
	var body map[string]any
	decodeResponse(t, response, &body)
	if body["apiVersion"] != float64(4) {
		t.Fatalf("apiVersion = %#v, want 4", body["apiVersion"])
	}
}

func TestLegacyAssignmentModeStrings(t *testing.T) {
	response := perform(t, newTestAPI(t), http.MethodPost, "/controller/network", `{
		"v4AssignMode":"zt",
		"v6AssignMode":"rfc4193,6plane"
	}`)
	if response.Code != http.StatusOK {
		t.Fatalf("create returned %d: %s", response.Code, response.Body.String())
	}
	var body struct {
		V4 legacyV4AssignMode `json:"v4AssignMode"`
		V6 legacyV6AssignMode `json:"v6AssignMode"`
	}
	decodeResponse(t, response, &body)
	if !body.V4.ZT || !body.V6.RFC4193 || !body.V6.SixPlane {
		t.Fatalf("assignment modes were not normalized: %+v", body)
	}
}

func TestLegacyUnstableCollections(t *testing.T) {
	api := newTestAPI(t)
	created := perform(t, api, http.MethodPost, "/controller/network", `{"name":"test"}`)
	var network map[string]any
	decodeResponse(t, created, &network)
	nwid := network["nwid"].(string)
	perform(t, api, http.MethodPost, "/controller/network/"+nwid+"/member/abcdef1234", `{"authorized":true}`)

	for _, path := range []string{
		"/unstable/controller/network",
		"/unstable/controller/network/" + nwid + "/member",
	} {
		response := perform(t, api, http.MethodGet, path, "")
		if response.Code != http.StatusOK || !json.Valid(response.Body.Bytes()) {
			t.Fatalf("%s returned %d: %s", path, response.Code, response.Body.String())
		}
	}
}

func TestLegacyPeerAndMemberRuntimeStatus(t *testing.T) {
	now := time.Date(2026, 7, 28, 12, 0, 0, 0, time.UTC)
	service, err := controller.New("8056c2e21c", memory.New(), func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	network, err := service.CreateNetwork(context.Background(), 1, "runtime")
	if err != nil {
		t.Fatal(err)
	}
	remote, err := identity.Generate(
		context.Background(),
		bytes.NewReader(bytes.Repeat([]byte{0x44}, identity.PrivateKeyLength)),
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.RegisterMember(context.Background(), network.ID, remote.Address()); err != nil {
		t.Fatal(err)
	}
	registry := peer.NewRegistry()
	if _, err := registry.LearnHello(packet.Hello{
		Identity: remote.Public(), ProtocolVersion: 13, Major: 1, Minor: 16, Revision: 2,
	}, packet.SessionKey{}, netip.MustParseAddrPort("198.51.100.10:43210"), now); err != nil {
		t.Fatal(err)
	}
	api := &legacyAPI{service: service, peers: registry, now: func() time.Time { return now.Add(time.Second) }}
	request := httptestRequestWithValues(
		http.MethodGet, "/controller/network/x/member/y",
		map[string]string{"networkID": string(network.ID), "nodeID": string(remote.Address())},
	)
	memberResponse := serveRequest(api.getMember, request)
	var member map[string]any
	decodeResponse(t, memberResponse, &member)
	if member["online"] != true || member["vMajor"] != float64(1) ||
		member["physicalAddress"] != "198.51.100.10:43210" {
		t.Fatalf("unexpected runtime member: %#v", member)
	}

	peers := serveRequest(api.listPeers, httptestRequestWithValues(http.MethodGet, "/peer", nil))
	var peerList []map[string]any
	decodeResponse(t, peers, &peerList)
	if len(peerList) != 1 || peerList[0]["address"] != string(remote.Address()) {
		t.Fatalf("unexpected peers: %#v", peerList)
	}
}

func httptestRequestWithValues(method, path string, values map[string]string) *http.Request {
	request := httptest.NewRequest(method, path, nil)
	for key, value := range values {
		request.SetPathValue(key, value)
	}
	return request
}

func serveRequest(handler http.HandlerFunc, request *http.Request) *httptest.ResponseRecorder {
	response := httptest.NewRecorder()
	handler(response, request)
	return response
}
