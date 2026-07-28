package httpapi

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"

	"github.com/alexlafalce/ZTGotroller/internal/controller"
	"github.com/alexlafalce/ZTGotroller/internal/domain"
	"github.com/alexlafalce/ZTGotroller/internal/store"
	"github.com/alexlafalce/ZTGotroller/internal/zerotier/peer"
	"github.com/alexlafalce/ZTGotroller/internal/zerotier/transport"
)

type Handler struct {
	service   *controller.Service
	peers     *peer.Registry
	upstreams *transport.UpstreamManager
	mux       *http.ServeMux
}

func New(service *controller.Service) http.Handler {
	return NewWithPeers(service, nil)
}

func NewWithPeers(service *controller.Service, peers *peer.Registry) http.Handler {
	return NewWithRuntime(service, peers, nil)
}

func NewWithRuntime(
	service *controller.Service,
	peers *peer.Registry,
	upstreams *transport.UpstreamManager,
) http.Handler {
	handler := &Handler{
		service: service, peers: peers, upstreams: upstreams, mux: http.NewServeMux(),
	}
	handler.mux.HandleFunc("GET /healthz", handler.health)
	handler.mux.HandleFunc("GET /metrics", handler.metrics)
	handler.mux.HandleFunc("POST /v1/networks", handler.createNetwork)
	handler.mux.HandleFunc("GET /v1/networks", handler.listNetworks)
	handler.mux.HandleFunc("GET /v1/networks/{networkID}", handler.getNetwork)
	handler.mux.HandleFunc("PUT /v1/networks/{networkID}", handler.updateNetwork)
	handler.mux.HandleFunc(
		"POST /v1/networks/{networkID}/members/{nodeID}",
		handler.registerMember,
	)
	handler.mux.HandleFunc(
		"GET /v1/networks/{networkID}/members",
		handler.listMembers,
	)
	handler.mux.HandleFunc(
		"GET /v1/networks/{networkID}/members/{nodeID}",
		handler.getMember,
	)
	handler.mux.HandleFunc(
		"PUT /v1/networks/{networkID}/members/{nodeID}",
		handler.updateMember,
	)
	handler.mux.HandleFunc(
		"PUT /v1/networks/{networkID}/members/{nodeID}/authorization",
		handler.setAuthorization,
	)
	registerLegacyRoutes(handler.mux, service, peers)
	return handler
}

func (handler *Handler) health(response http.ResponseWriter, request *http.Request) {
	networks, members, peerCount, err := handler.runtimeCounts(request)
	if err != nil {
		writeJSON(response, http.StatusServiceUnavailable, map[string]any{
			"status": "unavailable", "databaseReady": false, "error": err.Error(),
		})
		return
	}
	result := map[string]any{
		"status": "ok", "databaseReady": true,
		"controllerAddress": handler.service.ControllerID(),
		"networks":          networks, "members": members, "peers": peerCount,
	}
	if handler.upstreams != nil {
		result["upstreams"] = handler.upstreams.Status()
	}
	writeJSON(response, http.StatusOK, result)
}

func (handler *Handler) metrics(response http.ResponseWriter, request *http.Request) {
	networks, members, peerCount, err := handler.runtimeCounts(request)
	up := 1
	if err != nil {
		up = 0
	}
	response.Header().Set("Content-Type", "text/plain; version=0.0.4")
	_, _ = io.WriteString(response,
		"# HELP ztgotroller_up Whether persistence is available.\n"+
			"# TYPE ztgotroller_up gauge\nztgotroller_up "+strconv.Itoa(up)+"\n"+
			"# TYPE ztgotroller_networks gauge\nztgotroller_networks "+strconv.Itoa(networks)+"\n"+
			"# TYPE ztgotroller_members gauge\nztgotroller_members "+strconv.Itoa(members)+"\n"+
			"# TYPE ztgotroller_authenticated_peers gauge\nztgotroller_authenticated_peers "+
			strconv.Itoa(peerCount)+"\n",
	)
}

func (handler *Handler) runtimeCounts(request *http.Request) (int, int, int, error) {
	networks, err := handler.service.ListNetworks(request.Context())
	if err != nil {
		return 0, 0, 0, err
	}
	members := 0
	for _, network := range networks {
		list, err := handler.service.ListMembers(request.Context(), network.ID)
		if err != nil {
			return 0, 0, 0, err
		}
		members += len(list)
	}
	peerCount := 0
	if handler.peers != nil {
		peerCount = len(handler.peers.List())
	}
	return len(networks), members, peerCount, nil
}

func (handler *Handler) listNetworks(response http.ResponseWriter, request *http.Request) {
	networks, err := handler.service.ListNetworks(request.Context())
	if err != nil {
		writeError(response, err)
		return
	}
	writeJSON(response, http.StatusOK, networks)
}

func (handler *Handler) getNetwork(response http.ResponseWriter, request *http.Request) {
	networkID, ok := parseNetworkPath(response, request)
	if !ok {
		return
	}
	network, err := handler.service.GetNetwork(request.Context(), networkID)
	if err != nil {
		writeError(response, err)
		return
	}
	writeJSON(response, http.StatusOK, network)
}

func (handler *Handler) updateNetwork(response http.ResponseWriter, request *http.Request) {
	networkID, ok := parseNetworkPath(response, request)
	if !ok {
		return
	}
	var input struct {
		Revision uint64 `json:"revision"`
		controller.NetworkUpdate
	}
	if !decodeJSON(response, request, &input) {
		return
	}
	network, err := handler.service.UpdateNetwork(
		request.Context(), networkID, input.NetworkUpdate, input.Revision,
	)
	if err != nil {
		writeError(response, err)
		return
	}
	writeJSON(response, http.StatusOK, network)
}

func (handler *Handler) ServeHTTP(response http.ResponseWriter, request *http.Request) {
	handler.mux.ServeHTTP(response, request)
}

func (handler *Handler) createNetwork(response http.ResponseWriter, request *http.Request) {
	var input struct {
		Sequence uint32 `json:"sequence"`
		Name     string `json:"name"`
	}
	if !decodeJSON(response, request, &input) {
		return
	}
	network, err := handler.service.CreateNetwork(request.Context(), input.Sequence, input.Name)
	if err != nil {
		writeError(response, err)
		return
	}
	writeJSON(response, http.StatusCreated, network)
}

func (handler *Handler) registerMember(response http.ResponseWriter, request *http.Request) {
	networkID, ok := parseNetworkPath(response, request)
	if !ok {
		return
	}
	nodeID, ok := parseNodePath(response, request)
	if !ok {
		return
	}
	member, err := handler.service.RegisterMember(request.Context(), networkID, nodeID)
	if err != nil {
		writeError(response, err)
		return
	}
	writeJSON(response, http.StatusOK, member)
}

func (handler *Handler) listMembers(response http.ResponseWriter, request *http.Request) {
	networkID, ok := parseNetworkPath(response, request)
	if !ok {
		return
	}
	members, err := handler.service.ListMembers(request.Context(), networkID)
	if err != nil {
		writeError(response, err)
		return
	}
	writeJSON(response, http.StatusOK, members)
}

func (handler *Handler) getMember(response http.ResponseWriter, request *http.Request) {
	networkID, ok := parseNetworkPath(response, request)
	if !ok {
		return
	}
	nodeID, ok := parseNodePath(response, request)
	if !ok {
		return
	}
	member, err := handler.service.GetMember(request.Context(), networkID, nodeID)
	if err != nil {
		writeError(response, err)
		return
	}
	writeJSON(response, http.StatusOK, member)
}

func (handler *Handler) updateMember(response http.ResponseWriter, request *http.Request) {
	networkID, ok := parseNetworkPath(response, request)
	if !ok {
		return
	}
	nodeID, ok := parseNodePath(response, request)
	if !ok {
		return
	}
	var input struct {
		Revision uint64 `json:"revision"`
		controller.MemberUpdate
	}
	if !decodeJSON(response, request, &input) {
		return
	}
	member, err := handler.service.UpdateMember(
		request.Context(), networkID, nodeID, input.MemberUpdate, input.Revision,
	)
	if err != nil {
		writeError(response, err)
		return
	}
	writeJSON(response, http.StatusOK, member)
}

func (handler *Handler) setAuthorization(response http.ResponseWriter, request *http.Request) {
	networkID, ok := parseNetworkPath(response, request)
	if !ok {
		return
	}
	nodeID, ok := parseNodePath(response, request)
	if !ok {
		return
	}
	var input struct {
		Authorized bool   `json:"authorized"`
		Revision   uint64 `json:"revision"`
	}
	if !decodeJSON(response, request, &input) {
		return
	}
	member, err := handler.service.SetMemberAuthorization(
		request.Context(), networkID, nodeID, input.Authorized, input.Revision,
	)
	if err != nil {
		writeError(response, err)
		return
	}
	writeJSON(response, http.StatusOK, member)
}

func parseNetworkPath(response http.ResponseWriter, request *http.Request) (domain.NetworkID, bool) {
	networkID, err := domain.ParseNetworkID(request.PathValue("networkID"))
	if err != nil {
		writeJSON(response, http.StatusBadRequest, errorResponse{Error: err.Error()})
		return "", false
	}
	return networkID, true
}

func parseNodePath(response http.ResponseWriter, request *http.Request) (domain.NodeID, bool) {
	nodeID, err := domain.ParseNodeID(request.PathValue("nodeID"))
	if err != nil {
		writeJSON(response, http.StatusBadRequest, errorResponse{Error: err.Error()})
		return "", false
	}
	return nodeID, true
}

func decodeJSON(response http.ResponseWriter, request *http.Request, destination any) bool {
	decoder := json.NewDecoder(http.MaxBytesReader(response, request.Body, 1<<20))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		writeJSON(response, http.StatusBadRequest, errorResponse{Error: "invalid JSON body"})
		return false
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		writeJSON(response, http.StatusBadRequest, errorResponse{Error: "body must contain one JSON value"})
		return false
	}
	return true
}

type errorResponse struct {
	Error string `json:"error"`
}

func writeError(response http.ResponseWriter, err error) {
	status := http.StatusInternalServerError
	switch {
	case errors.Is(err, store.ErrNotFound):
		status = http.StatusNotFound
	case errors.Is(err, store.ErrAlreadyExists), errors.Is(err, store.ErrConflict):
		status = http.StatusConflict
	}
	writeJSON(response, status, errorResponse{Error: err.Error()})
}

func writeJSON(response http.ResponseWriter, status int, value any) {
	response.Header().Set("Content-Type", "application/json")
	response.WriteHeader(status)
	_ = json.NewEncoder(response).Encode(value)
}
