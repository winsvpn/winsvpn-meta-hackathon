// Package mobility selects authenticated Winn carriers without changing the
// logical VPN session or AWG generation.
package mobility

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"sort"
	"sync"
	"time"
)

type Carrier string

const (
	DirectUDP Carrier = "direct-udp"
	HTTP3     Carrier = "http3-connect-udp"
	HTTP2     Carrier = "http2-stream"
)

type Phase string

const (
	FailClosed Phase = "fail-closed"
	Online     Phase = "online"
	Probing    Phase = "probing"
	Recovering Phase = "recovering"
	Closed     Phase = "closed"
)

type Path struct {
	ID       string
	Carrier  Carrier
	Endpoint string
	Priority float64
}

type Observation struct {
	PathID     string
	Success    bool
	RTT        time.Duration
	Loss       float64
	Throughput float64
	At         time.Time
}

type Config struct {
	EWMAAlpha          float64
	LatencyWeight      float64
	LossWeight         float64
	ThroughputWeight   float64
	FailurePenalty     float64
	SwitchHysteresis   float64
	SwitchCooldown     time.Duration
	FailureCooldown    time.Duration
	MaxFailureCooldown time.Duration
}

func DefaultConfig() Config {
	return Config{
		EWMAAlpha:          0.25,
		LatencyWeight:      1,
		LossWeight:         400,
		ThroughputWeight:   10,
		FailurePenalty:     2_000,
		SwitchHysteresis:   25,
		SwitchCooldown:     15 * time.Second,
		FailureCooldown:    250 * time.Millisecond,
		MaxFailureCooldown: 30 * time.Second,
	}
}

type pathState struct {
	path                 Path
	observed             bool
	healthy              bool
	rttMillis            float64
	loss                 float64
	throughputMbps       float64
	consecutiveFailures  uint32
	ineligibleUntil      time.Time
	lastObservation      time.Time
	lastSuccessfulSample time.Time
}

type Snapshot struct {
	SessionID        string
	TunnelGeneration uint64
	Phase            Phase
	ActivePath       string
	LastSwitch       time.Time
	Switches         uint64
	Paths            []PathSnapshot
}

type PathSnapshot struct {
	Path                Path
	Healthy             bool
	RTT                 time.Duration
	Loss                float64
	ThroughputMbps      float64
	ConsecutiveFailures uint32
	IneligibleUntil     time.Time
	Score               float64
}

type Engine struct {
	mu               sync.Mutex
	config           Config
	sessionID        string
	tunnelGeneration uint64
	phase            Phase
	activePath       string
	lastActivePath   string
	lastSwitch       time.Time
	switches         uint64
	paths            map[string]*pathState
}

func New(sessionID string, tunnelGeneration uint64, paths []Path, config Config) (*Engine, error) {
	if !ValidSessionID(sessionID) {
		return nil, errors.New("session ID must be 32 lowercase hexadecimal characters")
	}
	if tunnelGeneration == 0 {
		return nil, errors.New("tunnel generation must be positive")
	}
	if err := validateConfig(config); err != nil {
		return nil, err
	}
	if len(paths) == 0 {
		return nil, errors.New("at least one carrier path is required")
	}
	engine := &Engine{
		config:           config,
		sessionID:        sessionID,
		tunnelGeneration: tunnelGeneration,
		phase:            FailClosed,
		paths:            make(map[string]*pathState, len(paths)),
	}
	for _, path := range paths {
		if path.ID == "" || path.Endpoint == "" {
			return nil, errors.New("path ID and endpoint are required")
		}
		switch path.Carrier {
		case DirectUDP, HTTP3, HTTP2:
		default:
			return nil, fmt.Errorf("unsupported carrier %q", path.Carrier)
		}
		if math.IsNaN(path.Priority) || math.IsInf(path.Priority, 0) {
			return nil, errors.New("path priority must be finite")
		}
		if _, duplicate := engine.paths[path.ID]; duplicate {
			return nil, fmt.Errorf("duplicate path ID %q", path.ID)
		}
		engine.paths[path.ID] = &pathState{path: path}
	}
	return engine, nil
}

func NewSessionID() (string, error) {
	var value [16]byte
	if _, err := rand.Read(value[:]); err != nil {
		return "", fmt.Errorf("generate session ID: %w", err)
	}
	return hex.EncodeToString(value[:]), nil
}

func ValidSessionID(value string) bool {
	if len(value) != 32 {
		return false
	}
	decoded, err := hex.DecodeString(value)
	if err != nil || len(decoded) != 16 {
		return false
	}
	return value == hex.EncodeToString(decoded)
}

func (e *Engine) BeginProbe() error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.phase == Closed {
		return errors.New("mobility engine is closed")
	}
	if e.activePath == "" {
		e.phase = Recovering
	} else {
		e.phase = Probing
	}
	return nil
}

func (e *Engine) Observe(observation Observation) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.phase == Closed {
		return errors.New("mobility engine is closed")
	}
	state, ok := e.paths[observation.PathID]
	if !ok {
		return fmt.Errorf("unknown path %q", observation.PathID)
	}
	if observation.At.IsZero() {
		return errors.New("observation time is required")
	}
	if observation.Loss < 0 || observation.Loss > 1 || math.IsNaN(observation.Loss) {
		return errors.New("loss must be between 0 and 1")
	}
	if observation.RTT < 0 || math.IsNaN(observation.Throughput) ||
		math.IsInf(observation.Throughput, 0) || observation.Throughput < 0 {
		return errors.New("RTT and throughput must be finite and non-negative")
	}
	state.lastObservation = observation.At
	if !observation.Success {
		state.healthy = false
		state.consecutiveFailures++
		state.loss = ewma(state.loss, 1, e.config.EWMAAlpha, state.observed)
		state.observed = true
		state.ineligibleUntil = observation.At.Add(e.failureCooldown(state.consecutiveFailures))
		if e.activePath == observation.PathID {
			e.activePath = ""
			e.phase = Recovering
		} else if e.activePath != "" {
			e.phase = Online
		}
		return nil
	}
	state.healthy = true
	state.consecutiveFailures = 0
	state.ineligibleUntil = time.Time{}
	state.rttMillis = ewma(state.rttMillis, float64(observation.RTT)/float64(time.Millisecond), e.config.EWMAAlpha, state.observed)
	state.loss = ewma(state.loss, observation.Loss, e.config.EWMAAlpha, state.observed)
	state.throughputMbps = ewma(state.throughputMbps, observation.Throughput, e.config.EWMAAlpha, state.observed)
	state.observed = true
	state.lastSuccessfulSample = observation.At
	return nil
}

// Select returns the best eligible path. It preserves a healthy active path
// unless the challenger clears both hysteresis and switch cooldown.
func (e *Engine) Select(now time.Time) (Path, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.phase == Closed {
		return Path{}, errors.New("mobility engine is closed")
	}
	if now.IsZero() {
		return Path{}, errors.New("selection time is required")
	}
	candidates := e.sortedEligible(now)
	if len(candidates) == 0 {
		e.phase = Recovering
		return Path{}, errors.New("no eligible carrier path")
	}
	best := candidates[0]
	if active := e.paths[e.activePath]; active != nil && active.healthy && !now.Before(active.ineligibleUntil) {
		if best.path.ID == active.path.ID {
			return active.path, nil
		}
		if now.Sub(e.lastSwitch) < e.config.SwitchCooldown ||
			e.score(active) <= e.score(best)+e.config.SwitchHysteresis {
			return active.path, nil
		}
	}
	return best.path, nil
}

// Activate atomically commits an already authenticated path. It never changes
// the session ID or tunnel generation.
func (e *Engine) Activate(pathID string, now time.Time) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.phase == Closed {
		return errors.New("mobility engine is closed")
	}
	if now.IsZero() {
		return errors.New("activation time is required")
	}
	state, ok := e.paths[pathID]
	if !ok {
		return fmt.Errorf("unknown path %q", pathID)
	}
	if !state.healthy || now.Before(state.ineligibleUntil) {
		return errors.New("path has not completed a successful probe")
	}
	if e.activePath != pathID {
		if e.lastActivePath != "" && e.lastActivePath != pathID {
			e.switches++
		}
		e.activePath = pathID
		e.lastActivePath = pathID
		e.lastSwitch = now
	}
	e.phase = Online
	return nil
}

func (e *Engine) Fail(pathID string, now time.Time) error {
	return e.Observe(Observation{PathID: pathID, Success: false, Loss: 1, At: now})
}

func (e *Engine) Close() {
	e.mu.Lock()
	e.phase = Closed
	e.activePath = ""
	e.mu.Unlock()
}

func (e *Engine) Snapshot(now time.Time) Snapshot {
	e.mu.Lock()
	defer e.mu.Unlock()
	snapshot := Snapshot{
		SessionID:        e.sessionID,
		TunnelGeneration: e.tunnelGeneration,
		Phase:            e.phase,
		ActivePath:       e.activePath,
		LastSwitch:       e.lastSwitch,
		Switches:         e.switches,
		Paths:            make([]PathSnapshot, 0, len(e.paths)),
	}
	for _, state := range e.paths {
		snapshot.Paths = append(snapshot.Paths, PathSnapshot{
			Path:                state.path,
			Healthy:             state.healthy,
			RTT:                 time.Duration(state.rttMillis * float64(time.Millisecond)),
			Loss:                state.loss,
			ThroughputMbps:      state.throughputMbps,
			ConsecutiveFailures: state.consecutiveFailures,
			IneligibleUntil:     state.ineligibleUntil,
			Score:               e.score(state),
		})
	}
	sort.Slice(snapshot.Paths, func(i, j int) bool {
		return snapshot.Paths[i].Path.ID < snapshot.Paths[j].Path.ID
	})
	return snapshot
}

func (e *Engine) sortedEligible(now time.Time) []*pathState {
	result := make([]*pathState, 0, len(e.paths))
	for _, state := range e.paths {
		if now.Before(state.ineligibleUntil) {
			continue
		}
		result = append(result, state)
	}
	sort.Slice(result, func(i, j int) bool {
		left, right := e.score(result[i]), e.score(result[j])
		if left == right {
			return result[i].path.ID < result[j].path.ID
		}
		return left < right
	})
	return result
}

func (e *Engine) score(state *pathState) float64 {
	score := state.path.Priority
	if !state.observed {
		return score + e.config.FailurePenalty/2
	}
	score += state.rttMillis * e.config.LatencyWeight
	score += state.loss * e.config.LossWeight
	score -= math.Log1p(state.throughputMbps) * e.config.ThroughputWeight
	score += float64(state.consecutiveFailures) * e.config.FailurePenalty
	return score
}

func (e *Engine) failureCooldown(failures uint32) time.Duration {
	if failures == 0 {
		return 0
	}
	multiplier := time.Duration(1)
	for index := uint32(1); index < failures && multiplier < 1<<20; index++ {
		multiplier *= 2
	}
	delay := e.config.FailureCooldown * multiplier
	if delay > e.config.MaxFailureCooldown {
		return e.config.MaxFailureCooldown
	}
	return delay
}

func ewma(previous, sample, alpha float64, initialized bool) float64 {
	if !initialized {
		return sample
	}
	return alpha*sample + (1-alpha)*previous
}

func validateConfig(config Config) error {
	if config.EWMAAlpha <= 0 || config.EWMAAlpha > 1 ||
		math.IsNaN(config.EWMAAlpha) {
		return errors.New("EWMA alpha must be in (0, 1]")
	}
	values := []float64{
		config.LatencyWeight,
		config.LossWeight,
		config.ThroughputWeight,
		config.FailurePenalty,
		config.SwitchHysteresis,
	}
	for _, value := range values {
		if value < 0 || math.IsNaN(value) || math.IsInf(value, 0) {
			return errors.New("mobility weights must be finite and non-negative")
		}
	}
	if config.SwitchCooldown < 0 || config.FailureCooldown <= 0 ||
		config.MaxFailureCooldown < config.FailureCooldown {
		return errors.New("invalid mobility cooldown configuration")
	}
	return nil
}
