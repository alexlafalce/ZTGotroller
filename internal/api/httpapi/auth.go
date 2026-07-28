package httpapi

import (
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"net/http"
	"strings"
)

func RequireBearerToken(next http.Handler, token string) (http.Handler, error) {
	if token == "" {
		return nil, errors.New("administrative API token is required")
	}
	expected := sha256.Sum256([]byte(token))
	return http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.URL.Path == "/healthz" {
			next.ServeHTTP(response, request)
			return
		}
		credential := request.Header.Get("X-ZT1-Auth")
		scheme, bearerCredential, found := strings.Cut(request.Header.Get("Authorization"), " ")
		if credential == "" && found && scheme == "Bearer" {
			credential = bearerCredential
		}
		provided := sha256.Sum256([]byte(credential))
		if subtle.ConstantTimeCompare(provided[:], expected[:]) != 1 {
			response.Header().Set("WWW-Authenticate", "Bearer, X-ZT1-Auth")
			writeJSON(response, http.StatusUnauthorized, errorResponse{Error: "unauthorized"})
			return
		}
		next.ServeHTTP(response, request)
	}), nil
}
