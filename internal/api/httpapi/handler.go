package httpapi

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"

	"github.com/alexlafalce/ZTGotroller/internal/controller"
	"github.com/alexlafalce/ZTGotroller/internal/domain"
	"github.com/alexlafalce/ZTGotroller/internal/store"
)

type Handler struct {
	service *controller.Service
	mux     *http.ServeMux
}

func New(service *controller.Service) http.Handler {
	handler := &Handler{service: service, mux: http.NewServeMux()}
	handler.mux.HandleFunc("GET /healthz", func(response http.ResponseWriter, _ *http.Request) {
		writeJSON(response, http.StatusOK, map[string]string{"status": "ok"})
	})
	handler.mux.HandleFunc("POST /v1/networks", handler.createNetwork)
	handler.mux.HandleFunc(
		"POST /v1/networks/{networkID}/members/{nodeID}",
		handler.registerMember,
	)
	handler.mux.HandleFunc(
		"PUT /v1/networks/{networkID}/members/{nodeID}/authorization",
		handler.setAuthorization,
	)
	return handler
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
	networkID, err := domain.ParseNetworkID(request.PathValue("networkID"))
	if err != nil {
		writeJSON(response, http.StatusBadRequest, errorResponse{Error: err.Error()})
		return
	}
	nodeID, err := domain.ParseNodeID(request.PathValue("nodeID"))
	if err != nil {
		writeJSON(response, http.StatusBadRequest, errorResponse{Error: err.Error()})
		return
	}
	member, err := handler.service.RegisterMember(request.Context(), networkID, nodeID)
	if err != nil {
		writeError(response, err)
		return
	}
	writeJSON(response, http.StatusOK, member)
}

func (handler *Handler) setAuthorization(response http.ResponseWriter, request *http.Request) {
	networkID, err := domain.ParseNetworkID(request.PathValue("networkID"))
	if err != nil {
		writeJSON(response, http.StatusBadRequest, errorResponse{Error: err.Error()})
		return
	}
	nodeID, err := domain.ParseNodeID(request.PathValue("nodeID"))
	if err != nil {
		writeJSON(response, http.StatusBadRequest, errorResponse{Error: err.Error()})
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
