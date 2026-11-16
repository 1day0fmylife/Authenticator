// Package api is the stdlib-only HTTP layer of the MFA verifier
// (SRV-001): routing, RFC 9457 problem responses, request IDs, panic
// recovery, body limits, security headers, privacy-preserving access logs
// and health endpoints. It contains no MFA logic yet.
package api

import (
	"encoding/json"
	"net/http"
)

// ProblemContentType is the RFC 9457 media type for error responses.
const ProblemContentType = "application/problem+json"

// Problem is an RFC 9457 problem details object with two extension members:
// a stable machine-readable Code and the RequestID for correlation.
//
// Detail is always a static, safe text: never user input, secrets, OTP
// codes, subject identifiers or internal error strings.
type Problem struct {
	Type      string `json:"type"`
	Title     string `json:"title"`
	Status    int    `json:"status"`
	Code      string `json:"code"`
	Detail    string `json:"detail,omitempty"`
	RequestID string `json:"request_id,omitempty"`
}

// Stable error codes. Clients must branch on Code, not on Title/Detail.
const (
	CodeNotFound         = "not_found"
	CodeMethodNotAllowed = "method_not_allowed"
	CodeBodyTooLarge     = "body_too_large"
	CodeInternal         = "internal_error"
	CodeNotReady         = "not_ready"
)

// WriteProblem writes a problem response. The type URI is a stable,
// non-dereferenceable URN so that no external host is implied.
func WriteProblem(w http.ResponseWriter, r *http.Request, status int, code, detail string) {
	p := Problem{
		Type:      "urn:authenticator:problem:" + code,
		Title:     http.StatusText(status),
		Status:    status,
		Code:      code,
		Detail:    detail,
		RequestID: RequestIDFrom(r.Context()),
	}
	w.Header().Set("Content-Type", ProblemContentType)
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(p)
}

// WriteJSON writes a JSON success response.
func WriteJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
