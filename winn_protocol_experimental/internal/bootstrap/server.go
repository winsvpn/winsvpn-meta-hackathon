package bootstrap

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log"
	"math"
	"mime"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"winsvpn.local/winnprotocol/internal/audit"
	"winsvpn.local/winnprotocol/internal/awg"
	"winsvpn.local/winnprotocol/internal/identity"
	"winsvpn.local/winnprotocol/internal/observability"
	"winsvpn.local/winnprotocol/internal/pqauth"
	"winsvpn.local/winnprotocol/internal/protocol"
	"winsvpn.local/winnprotocol/internal/ratelimit"
	"winsvpn.local/winnprotocol/internal/state"
	"winsvpn.local/winnprotocol/internal/tlsconfig"
)

const maxRequestBody = 32 << 10

type Server struct {
	Store          state.Controller
	Applier        awg.Applier
	Suite          tlsconfig.Suite
	ControllerID   string
	DeviceRegistry *pqauth.Registry
	Logger         *log.Logger
	Audit          audit.Sink
	Limiter        ratelimit.Limiter
	Metrics        *observability.Registry
	Concurrency    chan struct{}
	ApplyTimeout   time.Duration
	OnSuccess      func()
	logOnce        sync.Once
	logKey         [32]byte
	logKeyOK       bool
	marshalLog     func(any) ([]byte, error)
	latchMu        sync.Mutex
	latches        map[[32]byte]reconciliationLatch
}

type reconciliationLatch struct {
	ReasonCode      string
	RequestIDHash   [32]byte
	FirstFailureUTC time.Time
	ReleaseClass    string
	SnapshotHash    [32]byte
}

func (s *Server) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	writer.Header().Set("Cache-Control", "no-store")
	writer.Header().Set("X-Content-Type-Options", "nosniff")
	if s.Audit != nil && !s.Audit.Healthy() {
		if s.Metrics != nil {
			s.Metrics.Inc("audit_unavailable")
		}
		s.printLog("audit_unavailable", "", "", "tamper-evident audit sink is unhealthy")
		s.writeError(writer, http.StatusServiceUnavailable, "audit_unavailable", "controller audit sink is unavailable")
		return
	}
	if request.URL.Path != protocol.RekeyPath {
		s.writeError(writer, http.StatusNotFound, "not_found", "endpoint not found")
		return
	}
	if request.Method != http.MethodPost {
		writer.Header().Set("Allow", http.MethodPost)
		s.writeError(writer, http.StatusMethodNotAllowed, "method_not_allowed", "POST is required")
		return
	}
	if request.URL.RawQuery != "" {
		s.writeError(writer, http.StatusBadRequest, "invalid_request", "query parameters are forbidden")
		return
	}
	if s.Store == nil || s.Applier == nil {
		s.printLog("service_unconfigured", "", "", "state store or AWG adapter is unavailable")
		s.writeError(writer, http.StatusServiceUnavailable, "service_unconfigured", "controller service is unavailable")
		return
	}
	if s.Concurrency != nil {
		select {
		case s.Concurrency <- struct{}{}:
			defer func() { <-s.Concurrency }()
		default:
			s.log("capacity_rejected", "", "", "maximum concurrent requests reached")
			writer.Header().Set("Retry-After", "1")
			s.writeError(writer, http.StatusServiceUnavailable, "capacity_rejected", "controller is at request capacity")
			return
		}
	}
	if err := tlsconfig.ValidateState(request.TLS, s.Suite); err != nil {
		s.log("tls_profile_rejected", "", "", err.Error())
		s.writeError(writer, http.StatusUpgradeRequired, "tls_profile_rejected", "required TLS profile was not negotiated")
		return
	}
	deviceID, err := identity.DeviceID(request.TLS)
	if err != nil {
		s.log("device_identity_rejected", "", "", err.Error())
		s.writeError(writer, http.StatusUnauthorized, "device_identity_rejected", "valid device URI SAN is required")
		return
	}
	if s.Limiter != nil {
		allowed, retryAfter := s.Limiter.Allow(deviceID + "|" + remoteHost(request.RemoteAddr))
		if !allowed {
			retrySeconds := int(math.Ceil(retryAfter.Seconds()))
			if retrySeconds < 1 {
				retrySeconds = 1
			}
			writer.Header().Set("Retry-After", strconv.Itoa(retrySeconds))
			s.log("rate_limited", deviceID, "", "per-device/IP request budget exhausted")
			s.writeError(writer, http.StatusTooManyRequests, "rate_limited", "request rate limit exceeded")
			return
		}
	}
	mediaType, parameters, err := mime.ParseMediaType(request.Header.Get("Content-Type"))
	if err != nil || mediaType != protocol.MediaType || parameters["version"] != "2" || len(parameters) != 1 {
		s.writeError(writer, http.StatusUnsupportedMediaType, "unsupported_media_type", "Winn Protocol v2 media type is required")
		return
	}
	acceptType, acceptParameters, err := mime.ParseMediaType(request.Header.Get("Accept"))
	if err != nil || acceptType != protocol.MediaType || acceptParameters["version"] != "2" || len(acceptParameters) != 1 {
		s.writeError(writer, http.StatusNotAcceptable, "unsupported_response_type", "Winn Protocol v2 response media type is required")
		return
	}
	if request.Header.Get("Content-Encoding") != "" {
		s.writeError(writer, http.StatusUnsupportedMediaType, "unsupported_content_encoding", "content encoding is forbidden")
		return
	}
	request.Body = http.MaxBytesReader(writer, request.Body, maxRequestBody)
	decoder := json.NewDecoder(request.Body)
	decoder.DisallowUnknownFields()
	var rekeyRequest protocol.RekeyRequest
	if err := decoder.Decode(&rekeyRequest); err != nil {
		var bodyTooLarge *http.MaxBytesError
		if errors.As(err, &bodyTooLarge) {
			s.writeError(writer, http.StatusRequestEntityTooLarge, "request_too_large", "request exceeds the protocol limit")
			return
		}
		s.writeError(writer, http.StatusBadRequest, "invalid_request", "request JSON is invalid")
		return
	}
	if err := requireJSONEOF(decoder); err != nil {
		s.writeError(writer, http.StatusBadRequest, "invalid_request", "request must contain one JSON object")
		return
	}
	if err := protocol.ValidateRequest(rekeyRequest); err != nil {
		s.log("request_rejected", deviceID, rekeyRequest.RequestID, err.Error())
		s.writeError(writer, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	if rekeyRequest.Suite != s.Suite.Name {
		s.writeError(writer, http.StatusUpgradeRequired, "suite_mismatch", "request suite does not match this endpoint")
		return
	}
	if rekeyRequest.ControllerID != s.ControllerID {
		s.writeError(writer, http.StatusUnauthorized, "controller_identity_mismatch", "request is signed for a different controller")
		return
	}
	if rekeyRequest.DeviceID != deviceID {
		s.log("identity_mismatch", deviceID, rekeyRequest.RequestID, "request device ID differs from certificate")
		s.writeError(writer, http.StatusUnauthorized, "identity_mismatch", "request identity does not match device certificate")
		return
	}
	if s.DeviceRegistry == nil {
		s.log("pq_registry_unavailable", deviceID, rekeyRequest.RequestID, "device registry is not configured")
		s.writeError(writer, http.StatusServiceUnavailable, "pq_registry_unavailable", "PQ authentication registry is unavailable")
		return
	}
	deviceVerifier, err := s.DeviceRegistry.Verifier(deviceID, rekeyRequest.AuthAlgorithm, rekeyRequest.AuthKeyID)
	if err != nil {
		s.log("pq_auth_rejected", deviceID, rekeyRequest.RequestID, err.Error())
		s.writeError(writer, http.StatusUnauthorized, "pq_auth_rejected", "device PQ authentication key is not registered")
		return
	}
	if err := pqauth.VerifyRequest(rekeyRequest, deviceVerifier); err != nil {
		s.log("pq_auth_rejected", deviceID, rekeyRequest.RequestID, err.Error())
		s.writeError(writer, http.StatusUnauthorized, "pq_auth_rejected", "device ML-DSA signature is invalid")
		return
	}

	transactionSource, ok := s.Store.(state.TunnelTransactionSource)
	if !ok {
		s.log("controller_reconciliation_unavailable", deviceID, rekeyRequest.RequestID, "")
		s.writeError(writer, http.StatusServiceUnavailable, "controller_reconciliation_unavailable", "controller reconciliation is unavailable")
		return
	}
	transaction, err := transactionSource.BeginTunnelTransaction(
		request.Context(), rekeyRequest.DeviceID, rekeyRequest.PeerPublicKey,
	)
	if err != nil {
		s.log("controller_transaction_unavailable", deviceID, rekeyRequest.RequestID, "")
		s.writeError(writer, http.StatusServiceUnavailable, "controller_reconciliation_required", "controller reconciliation is required")
		return
	}
	tunnelKey := serverTunnelDigest(rekeyRequest)
	s.latchMu.Lock()
	_, latched := s.latches[tunnelKey]
	s.latchMu.Unlock()
	if latched {
		_ = transaction.Release(request.Context())
		s.writeError(writer, http.StatusServiceUnavailable, "controller_reconciliation_required", "controller reconciliation is required")
		return
	}
	release := func() bool {
		releaseCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		err := transaction.Release(releaseCtx)
		cancel()
		if err != nil {
			s.latch(tunnelKey, "lease_release_failure", rekeyRequest.RequestID, [32]byte{})
			s.log("lease_release_failed", deviceID, rekeyRequest.RequestID, "")
			s.writeError(writer, http.StatusServiceUnavailable, "controller_reconciliation_required", "controller reconciliation is required")
			return false
		}
		return true
	}
	prepared, err := transaction.Prepare(request.Context(), rekeyRequest)
	if err != nil {
		if !release() {
			return
		}
		s.handleStoreError(writer, deviceID, rekeyRequest.RequestID, err)
		return
	}
	defer clear(prepared.PSK)
	if !prepared.Committed {
		currentSource, ok := s.Applier.(awg.CurrentPSKSource)
		if !ok {
			s.latch(tunnelKey, "current_psk_unavailable", rekeyRequest.RequestID, [32]byte{})
			if !release() {
				return
			}
			s.writeError(writer, http.StatusServiceUnavailable, "controller_reconciliation_required", "controller reconciliation is required")
			return
		}
		timeout := s.ApplyTimeout
		if timeout <= 0 {
			timeout = 8 * time.Second
		}
		ctx, cancel := contextWithTimeout(request, timeout)
		oldPSK, readErr := currentSource.ReadCurrentPSK(ctx, prepared.Response.PeerPublicKey)
		if readErr != nil {
			cancel()
			if !release() {
				return
			}
			s.log("current_psk_read_failed", deviceID, rekeyRequest.RequestID, "")
			s.writeError(writer, http.StatusServiceUnavailable, "current_psk_read_failed", "controller could not read the active key")
			return
		}
		defer clear(oldPSK)
		applyErr := s.Applier.Apply(ctx, prepared.Response.PeerPublicKey, prepared.PSK)
		cancel()
		if applyErr != nil {
			if !release() {
				return
			}
			s.log("server_apply_failed", deviceID, rekeyRequest.RequestID, "")
			s.writeError(writer, http.StatusServiceUnavailable, "server_apply_failed", "controller AWG peer did not accept the new key")
			return
		}
		if err := transaction.Commit(request.Context(), rekeyRequest.RequestID); err != nil {
			first, firstErr := transaction.ReconcileCommitOutcome(request.Context(), rekeyRequest)
			defer clear(first.PSK)
			if firstErr == nil && snapshotMatchesPrepared(first, prepared) &&
				first.Disposition == state.CommitCommitted {
				s.log("commit_ack_recovered", deviceID, rekeyRequest.RequestID, "")
			} else if firstErr == nil && snapshotMatchesPrepared(first, prepared) &&
				first.Disposition == state.CommitUncommitted {
				second, secondErr := transaction.ReconcileCommitOutcome(request.Context(), rekeyRequest)
				if secondErr != nil || !snapshotEqual(first, second) ||
					second.Disposition != state.CommitUncommitted {
					clear(second.PSK)
					s.latch(tunnelKey, "commit_outcome_indeterminate", rekeyRequest.RequestID, first.SnapshotHash)
					if !release() {
						return
					}
					s.writeError(writer, http.StatusServiceUnavailable, "commit_outcome_indeterminate", "controller reconciliation is required")
					return
				}
				clear(second.PSK)
				rollbackCtx, rollbackCancel := context.WithTimeout(context.Background(), timeout)
				rollbackErr := s.Applier.Apply(rollbackCtx, prepared.Response.PeerPublicKey, oldPSK)
				rollbackCancel()
				if rollbackErr != nil {
					s.latch(tunnelKey, "commit_failed_rollback_failed", rekeyRequest.RequestID, second.SnapshotHash)
					if !release() {
						return
					}
					s.writeError(writer, http.StatusServiceUnavailable, "commit_failed_rollback_failed", "controller reconciliation is required")
					return
				}
				if !release() {
					return
				}
				s.writeError(writer, http.StatusServiceUnavailable, "commit_failed_rolled_back", "controller reverted the active key")
				return
			} else {
				s.latch(tunnelKey, "commit_outcome_indeterminate", rekeyRequest.RequestID, first.SnapshotHash)
				if !release() {
					return
				}
				s.writeError(writer, http.StatusServiceUnavailable, "commit_outcome_indeterminate", "controller reconciliation is required")
				return
			}
		}
	}
	if !release() {
		return
	}

	status := http.StatusCreated
	if prepared.Idempotent {
		status = http.StatusOK
	}
	writer.Header().Set("Content-Type", protocol.MediaType+";version=2")
	writer.WriteHeader(status)
	if err := json.NewEncoder(writer).Encode(prepared.Response); err != nil {
		s.log("response_write_failed", deviceID, rekeyRequest.RequestID, err.Error())
		return
	}
	s.log("rekey_committed", deviceID, rekeyRequest.RequestID, "generation="+uintToString(prepared.Response.Generation)+" suite="+s.Suite.Name)
	if s.OnSuccess != nil {
		s.OnSuccess()
	}
}

func (s *Server) handleStoreError(writer http.ResponseWriter, deviceID, requestID string, err error) {
	switch {
	case errors.Is(err, state.ErrRevoked):
		s.log("revoked_device_rejected", deviceID, requestID, err.Error())
		s.writeError(writer, http.StatusForbidden, "device_revoked", "device is revoked")
	case errors.Is(err, state.ErrReplayConflict):
		s.log("replay_rejected", deviceID, requestID, err.Error())
		s.writeError(writer, http.StatusConflict, "replay_conflict", "request ID was already used with different content")
	case errors.Is(err, state.ErrGenerationConflict):
		s.log("generation_rejected", deviceID, requestID, err.Error())
		s.writeError(writer, http.StatusConflict, "generation_conflict", err.Error())
	case errors.Is(err, state.ErrRotationPending):
		s.log("pending_rotation_rejected", deviceID, requestID, err.Error())
		s.writeError(writer, http.StatusConflict, "rotation_pending", err.Error())
	default:
		s.log("controller_state_error", deviceID, requestID, err.Error())
		s.writeError(writer, http.StatusInternalServerError, "controller_state_error", "controller state operation failed")
	}
}

func (s *Server) writeError(writer http.ResponseWriter, status int, code, message string) {
	writer.Header().Set("Content-Type", "application/json")
	writer.WriteHeader(status)
	_ = json.NewEncoder(writer).Encode(protocol.ErrorResponse{Code: code, Message: message})
}

func (s *Server) log(event, deviceID, requestID, detail string) {
	if s.Metrics != nil {
		s.Metrics.Inc(event)
	}
	if s.Audit != nil {
		if err := s.Audit.Record(event, deviceID, requestID, detail); err != nil {
			if s.Metrics != nil {
				s.Metrics.Inc("audit_write_failed")
			}
			s.printLog("audit_write_failed", deviceID, requestID, err.Error())
		}
	}
	s.printLog(event, deviceID, requestID, detail)
}

func (s *Server) printLog(event, deviceID, requestID, detail string) {
	if s.Logger == nil {
		return
	}
	s.logOnce.Do(func() {
		_, err := rand.Read(s.logKey[:])
		s.logKeyOK = err == nil
		if s.marshalLog == nil {
			s.marshalLog = json.Marshal
		}
	})
	record := map[string]string{
		"event":       closedLogCode(event),
		"detail_code": closedLogCode(event),
	}
	if s.logKeyOK && requestID != "" {
		mac := hmac.New(sha256.New, s.logKey[:])
		_, _ = mac.Write([]byte("winn-operational-request-correlation/v1"))
		_, _ = mac.Write([]byte{0})
		_, _ = mac.Write([]byte(requestID))
		record["request_correlation"] = hex.EncodeToString(mac.Sum(nil))
	}
	unsafeValues := identityAliases(deviceID)
	if recordContainsAny(record, unsafeValues) {
		record = map[string]string{}
	}
	encoded, err := s.marshalLog(record)
	if err != nil || len(encoded) == 0 || !validOperationalJSON(encoded) ||
		recordContainsBytes(encoded, unsafeValues) {
		encoded = []byte(`{"event":"operational_log_encode_failed","detail":"operational log record unavailable"}`)
		if recordContainsBytes(encoded, unsafeValues) {
			encoded = []byte(`{}`)
		}
	}
	s.Logger.Print(string(encoded))
}

func validOperationalJSON(encoded []byte) bool {
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	var record map[string]string
	if err := decoder.Decode(&record); err != nil || record == nil {
		return false
	}
	if err := requireJSONEOF(decoder); err != nil {
		return false
	}
	for key := range record {
		switch key {
		case "event", "detail_code", "request_correlation":
		default:
			return false
		}
	}
	return record["event"] != "" && record["detail_code"] != ""
}

func (s *Server) latch(
	key [32]byte,
	reason string,
	requestID string,
	snapshotHash [32]byte,
) {
	s.latchMu.Lock()
	defer s.latchMu.Unlock()
	if s.latches == nil {
		s.latches = make(map[[32]byte]reconciliationLatch)
	}
	if _, exists := s.latches[key]; !exists {
		s.latches[key] = reconciliationLatch{
			ReasonCode:      closedLogCode(reason),
			RequestIDHash:   sha256.Sum256([]byte(requestID)),
			FirstFailureUTC: time.Now().UTC(),
			ReleaseClass:    closedLogCode(reason),
			SnapshotHash:    snapshotHash,
		}
	}
}

func serverTunnelDigest(req protocol.RekeyRequest) [32]byte {
	h := sha256.New()
	_, _ = h.Write([]byte("winn-server-tunnel-latch/v1"))
	for _, value := range []string{req.ControllerID, req.DeviceID, req.PeerPublicKey} {
		_, _ = h.Write([]byte{0})
		_, _ = h.Write([]byte(value))
	}
	var result [32]byte
	copy(result[:], h.Sum(nil))
	return result
}

func snapshotMatchesPrepared(snapshot state.CommitSnapshot, prepared state.Prepared) bool {
	return responsesEqual(snapshot.Response, prepared.Response) &&
		bytes.Equal(snapshot.PSK, prepared.PSK)
}

func responsesEqual(first, second protocol.RekeyResponse) bool {
	left, leftErr := json.Marshal(first)
	right, rightErr := json.Marshal(second)
	if leftErr != nil || rightErr != nil {
		clear(left)
		clear(right)
		return false
	}
	equal := hmac.Equal(left, right)
	clear(left)
	clear(right)
	return equal
}

func snapshotEqual(first, second state.CommitSnapshot) bool {
	return first.Disposition == second.Disposition &&
		first.RequestDigest == second.RequestDigest &&
		first.SnapshotHash == second.SnapshotHash &&
		first.Response.RequestID == second.Response.RequestID &&
		first.Response.PresharedKey == second.Response.PresharedKey &&
		bytes.Equal(first.PSK, second.PSK)
}

func closedLogCode(value string) string {
	var builder strings.Builder
	for _, current := range value {
		if current >= 'a' && current <= 'z' || current >= '0' && current <= '9' || current == '_' {
			builder.WriteRune(current)
		}
	}
	if builder.Len() == 0 {
		return "unavailable"
	}
	return builder.String()
}

func identityAliases(deviceID string) [][]byte {
	if deviceID == "" {
		return nil
	}
	raw := []byte(deviceID)
	aliases := [][]byte{
		append([]byte(nil), raw...),
		[]byte(hex.EncodeToString(raw)),
		[]byte(strings.ToUpper(hex.EncodeToString(raw))),
		[]byte(base64.StdEncoding.EncodeToString(raw)),
		[]byte(base64.RawStdEncoding.EncodeToString(raw)),
		[]byte(base64.URLEncoding.EncodeToString(raw)),
		[]byte(base64.RawURLEncoding.EncodeToString(raw)),
	}
	return aliases
}

func recordContainsAny(record map[string]string, aliases [][]byte) bool {
	for key, value := range record {
		if recordContainsBytes([]byte(key), aliases) || recordContainsBytes([]byte(value), aliases) {
			return true
		}
	}
	return false
}

func recordContainsBytes(value []byte, aliases [][]byte) bool {
	for _, alias := range aliases {
		if len(alias) > 0 && bytes.Contains(value, alias) {
			return true
		}
	}
	return false
}

func remoteHost(remoteAddress string) string {
	host, _, err := net.SplitHostPort(remoteAddress)
	if err == nil && host != "" {
		return host
	}
	if remoteAddress == "" {
		return "unknown"
	}
	return remoteAddress
}

func requireJSONEOF(decoder *json.Decoder) error {
	var extra any
	err := decoder.Decode(&extra)
	if errors.Is(err, io.EOF) {
		return nil
	}
	if err == nil {
		return errors.New("extra JSON value")
	}
	return err
}
