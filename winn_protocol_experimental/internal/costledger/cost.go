// Package costledger validates provider-tagged cloud inventory and produces
// conservative recurring-cost projections without combining currencies.
package costledger

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"math/bits"
	"regexp"
	"slices"
	"strings"
	"time"
)

const (
	FormatV1         = "winn-cloud-cost/v1"
	maxAccounts      = 16
	maxResources     = 1024
	maxMoneyMicros   = uint64(1_000_000_000_000_000)
	maxBillingPeriod = 366 * 24 * time.Hour
)

var (
	identifierPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._:-]{0,127}$`)
	currencyPattern   = regexp.MustCompile(`^[A-Z]{3}$`)
	sha256Pattern     = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

type Snapshot struct {
	Format        string     `json:"format"`
	ObservedAt    time.Time  `json:"observed_at"`
	TreeDigest    string     `json:"tree_digest,omitempty"`
	Accounts      []Account  `json:"accounts"`
	Resources     []Resource `json:"resources"`
	Connections   uint64     `json:"connections,omitempty"`
	EgressBytes   uint64     `json:"egress_bytes,omitempty"`
	WindowSeconds uint64     `json:"window_seconds,omitempty"`
}

type Account struct {
	Provider              string `json:"provider"`
	Currency              string `json:"currency"`
	AvailableCreditMicros uint64 `json:"available_credit_micros"`
	CurrentChargesMicros  uint64 `json:"current_charges_micros"`
	HistoricalUsageMicros uint64 `json:"historical_usage_micros,omitempty"`
	Source                string `json:"source"`
}

type Resource struct {
	Provider             string `json:"provider"`
	ResourceID           string `json:"resource_id"`
	Role                 string `json:"role"`
	Phase                string `json:"phase"`
	Region               string `json:"region"`
	Currency             string `json:"currency"`
	RateMicros           uint64 `json:"rate_micros"`
	BillingPeriodSeconds uint64 `json:"billing_period_seconds"`
	Quantity             uint32 `json:"quantity"`
}

type Report struct {
	Format        string       `json:"format"`
	ObservedAt    time.Time    `json:"observed_at"`
	GeneratedAt   time.Time    `json:"generated_at"`
	TreeDigest    string       `json:"tree_digest,omitempty"`
	Scopes        []Projection `json:"scopes"`
	Connections   uint64       `json:"connections,omitempty"`
	EgressBytes   uint64       `json:"egress_bytes,omitempty"`
	WindowSeconds uint64       `json:"window_seconds,omitempty"`
}

type Projection struct {
	Provider                  string `json:"provider"`
	Currency                  string `json:"currency"`
	ResourceCount             int    `json:"resource_count"`
	AvailableCreditMicros     uint64 `json:"available_credit_micros"`
	CurrentChargesMicros      uint64 `json:"current_charges_micros"`
	HistoricalUsageMicros     uint64 `json:"historical_usage_micros,omitempty"`
	Cost24HoursMicros         uint64 `json:"cost_24_hours_micros"`
	Cost72HoursMicros         uint64 `json:"cost_72_hours_micros"`
	Cost7DaysMicros           uint64 `json:"cost_7_days_micros"`
	Cost30DaysMicros          uint64 `json:"cost_30_days_micros"`
	RemainingAfter7DaysMicros uint64 `json:"remaining_after_7_days_micros"`
	RunwayHours               uint64 `json:"runway_hours,omitempty"`
	CostPer10000Connections   uint64 `json:"cost_per_10000_connections_micros,omitempty"`
	CostPerTransferredTB      uint64 `json:"cost_per_transferred_tb_micros,omitempty"`
}

type scopeKey struct {
	provider string
	currency string
}

type accumulator struct {
	projection Projection
	resources  []Resource
}

func Decode(reader io.Reader) (Snapshot, error) {
	if reader == nil {
		return Snapshot{}, errors.New("cost snapshot reader is required")
	}
	decoder := json.NewDecoder(io.LimitReader(reader, 4<<20))
	decoder.DisallowUnknownFields()
	var snapshot Snapshot
	if err := decoder.Decode(&snapshot); err != nil {
		return Snapshot{}, fmt.Errorf("decode cost snapshot: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return Snapshot{}, errors.New("cost snapshot has trailing JSON")
		}
		return Snapshot{}, fmt.Errorf("decode cost snapshot trailing data: %w", err)
	}
	if err := snapshot.Validate(); err != nil {
		return Snapshot{}, err
	}
	return snapshot, nil
}

func Encode(snapshot Snapshot) ([]byte, error) {
	if err := snapshot.Validate(); err != nil {
		return nil, err
	}
	data, err := json.MarshalIndent(snapshot, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("encode cost snapshot: %w", err)
	}
	return append(data, '\n'), nil
}

func (snapshot Snapshot) Validate() error {
	if snapshot.Format != FormatV1 {
		return errors.New("cost snapshot format is unsupported")
	}
	if !isUTCTimestamp(snapshot.ObservedAt) ||
		snapshot.ObservedAt.After(time.Now().UTC().Add(5*time.Minute)) {
		return errors.New("cost snapshot observed_at must be a plausible UTC time")
	}
	if snapshot.TreeDigest != "" && !sha256Pattern.MatchString(snapshot.TreeDigest) {
		return errors.New("cost snapshot tree digest is invalid")
	}
	if len(snapshot.Accounts) == 0 || len(snapshot.Accounts) > maxAccounts {
		return errors.New("cost snapshot account count is invalid")
	}
	if len(snapshot.Resources) > maxResources {
		return errors.New("cost snapshot resource count is invalid")
	}
	if (snapshot.WindowSeconds == 0) !=
		(snapshot.Connections == 0 && snapshot.EgressBytes == 0) {
		return errors.New("usage counters require a nonzero measurement window")
	}
	if snapshot.WindowSeconds > uint64(maxBillingPeriod/time.Second) {
		return errors.New("measurement window exceeds limit")
	}

	accounts := make(map[scopeKey]struct{}, len(snapshot.Accounts))
	for index, account := range snapshot.Accounts {
		if err := account.validate(); err != nil {
			return fmt.Errorf("account %d: %w", index, err)
		}
		key := scopeKey{provider: account.Provider, currency: account.Currency}
		if _, duplicate := accounts[key]; duplicate {
			return fmt.Errorf("account %d duplicates provider/currency scope", index)
		}
		accounts[key] = struct{}{}
	}

	resources := make(map[string]struct{}, len(snapshot.Resources))
	for index, resource := range snapshot.Resources {
		if err := resource.validate(); err != nil {
			return fmt.Errorf("resource %d: %w", index, err)
		}
		key := scopeKey{provider: resource.Provider, currency: resource.Currency}
		if _, exists := accounts[key]; !exists {
			return fmt.Errorf("resource %d has no matching account scope", index)
		}
		resourceKey := resource.Provider + "\x00" + resource.ResourceID
		if _, duplicate := resources[resourceKey]; duplicate {
			return fmt.Errorf("resource %d repeats provider resource ID", index)
		}
		resources[resourceKey] = struct{}{}
	}
	return nil
}

func (account Account) validate() error {
	if !identifierPattern.MatchString(account.Provider) {
		return errors.New("provider is invalid")
	}
	if !currencyPattern.MatchString(account.Currency) {
		return errors.New("currency must be an ISO-style three-letter code")
	}
	if account.AvailableCreditMicros > maxMoneyMicros ||
		account.CurrentChargesMicros > maxMoneyMicros ||
		account.HistoricalUsageMicros > maxMoneyMicros {
		return errors.New("account monetary value exceeds limit")
	}
	if strings.TrimSpace(account.Source) == "" || len(account.Source) > 512 {
		return errors.New("account evidence source is required")
	}
	return nil
}

func (resource Resource) validate() error {
	for name, value := range map[string]string{
		"provider":    resource.Provider,
		"resource ID": resource.ResourceID,
		"role":        resource.Role,
		"phase":       resource.Phase,
		"region":      resource.Region,
	} {
		if !identifierPattern.MatchString(value) {
			return fmt.Errorf("%s is invalid", name)
		}
	}
	if !currencyPattern.MatchString(resource.Currency) {
		return errors.New("currency must be an ISO-style three-letter code")
	}
	if resource.RateMicros == 0 || resource.RateMicros > maxMoneyMicros {
		return errors.New("recurring rate is invalid")
	}
	if resource.BillingPeriodSeconds == 0 ||
		resource.BillingPeriodSeconds > uint64(maxBillingPeriod/time.Second) {
		return errors.New("billing period is invalid")
	}
	if resource.Quantity == 0 || resource.Quantity > 1024 {
		return errors.New("quantity is invalid")
	}
	return nil
}

func Project(snapshot Snapshot, generatedAt time.Time) (Report, error) {
	if err := snapshot.Validate(); err != nil {
		return Report{}, err
	}
	if !isUTCTimestamp(generatedAt) {
		return Report{}, errors.New("report generation time must be UTC")
	}

	scopes := make(map[scopeKey]*accumulator, len(snapshot.Accounts))
	for _, account := range snapshot.Accounts {
		key := scopeKey{provider: account.Provider, currency: account.Currency}
		scopes[key] = &accumulator{projection: Projection{
			Provider:              account.Provider,
			Currency:              account.Currency,
			AvailableCreditMicros: account.AvailableCreditMicros,
			CurrentChargesMicros:  account.CurrentChargesMicros,
			HistoricalUsageMicros: account.HistoricalUsageMicros,
		}}
	}
	for _, resource := range snapshot.Resources {
		key := scopeKey{provider: resource.Provider, currency: resource.Currency}
		scope := scopes[key]
		scope.resources = append(scope.resources, resource)
		scope.projection.ResourceCount += int(resource.Quantity)
	}

	report := Report{
		Format:        FormatV1,
		ObservedAt:    snapshot.ObservedAt,
		GeneratedAt:   generatedAt,
		TreeDigest:    snapshot.TreeDigest,
		Connections:   snapshot.Connections,
		EgressBytes:   snapshot.EgressBytes,
		WindowSeconds: snapshot.WindowSeconds,
		Scopes:        make([]Projection, 0, len(scopes)),
	}
	for _, scope := range scopes {
		var err error
		scope.projection.Cost24HoursMicros, err =
			projectResources(scope.resources, 24*time.Hour)
		if err != nil {
			return Report{}, err
		}
		scope.projection.Cost72HoursMicros, err =
			projectResources(scope.resources, 72*time.Hour)
		if err != nil {
			return Report{}, err
		}
		scope.projection.Cost7DaysMicros, err =
			projectResources(scope.resources, 7*24*time.Hour)
		if err != nil {
			return Report{}, err
		}
		scope.projection.Cost30DaysMicros, err =
			projectResources(scope.resources, 30*24*time.Hour)
		if err != nil {
			return Report{}, err
		}
		if scope.projection.AvailableCreditMicros >
			scope.projection.Cost7DaysMicros {
			scope.projection.RemainingAfter7DaysMicros =
				scope.projection.AvailableCreditMicros -
					scope.projection.Cost7DaysMicros
		}
		if scope.projection.Cost24HoursMicros > 0 {
			scope.projection.RunwayHours = mulDivFloor(
				scope.projection.AvailableCreditMicros,
				24,
				scope.projection.Cost24HoursMicros,
			)
		}
		if snapshot.WindowSeconds > 0 {
			// #nosec G115 -- Validate above rejects WindowSeconds greater than
			// maxBillingPeriod/time.Second (366 days), far under the int64
			// seconds range, so this conversion cannot overflow.
			windowHorizon := time.Duration(snapshot.WindowSeconds) * time.Second
			windowCost, costErr := projectResources(scope.resources, windowHorizon)
			if costErr != nil {
				return Report{}, costErr
			}
			if snapshot.Connections > 0 {
				unitCost, unitErr := mulDivCeilChecked(windowCost, 10_000, snapshot.Connections)
				if unitErr != nil {
					return Report{}, unitErr
				}
				scope.projection.CostPer10000Connections = unitCost
			}
			if snapshot.EgressBytes > 0 {
				const decimalTB = uint64(1_000_000_000_000)
				unitCost, unitErr := mulDivCeilChecked(windowCost, decimalTB, snapshot.EgressBytes)
				if unitErr != nil {
					return Report{}, unitErr
				}
				scope.projection.CostPerTransferredTB = unitCost
			}
		}
		report.Scopes = append(report.Scopes, scope.projection)
	}
	slices.SortFunc(report.Scopes, func(first, second Projection) int {
		if compared := strings.Compare(first.Provider, second.Provider); compared != 0 {
			return compared
		}
		return strings.Compare(first.Currency, second.Currency)
	})
	return report, nil
}

func projectResources(resources []Resource, horizon time.Duration) (uint64, error) {
	if horizon < 0 {
		return 0, errors.New("cost projection horizon is invalid")
	}
	seconds := uint64(horizon / time.Second)
	var total uint64
	for _, resource := range resources {
		quantityRate, overflow := multiply(resource.RateMicros, uint64(resource.Quantity))
		if overflow {
			return 0, errors.New("cost projection overflows")
		}
		cost, costErr := mulDivCeilChecked(quantityRate, seconds, resource.BillingPeriodSeconds)
		if costErr != nil {
			return 0, costErr
		}
		if math.MaxUint64-total < cost {
			return 0, errors.New("cost projection total overflows")
		}
		total += cost
	}
	return total, nil
}

func multiply(first, second uint64) (uint64, bool) {
	if first != 0 && second > math.MaxUint64/first {
		return 0, true
	}
	return first * second, false
}

func mulDivCeil(first, second, divisor uint64) uint64 {
	if divisor == 0 || first == 0 || second == 0 {
		return 0
	}
	high, low := bits.Mul64(first, second)
	if high >= divisor {
		return math.MaxUint64
	}
	quotient, remainder := bits.Div64(high, low, divisor)
	if remainder == 0 {
		return quotient
	}
	if quotient == math.MaxUint64 {
		return math.MaxUint64
	}
	return quotient + 1
}

func mulDivCeilChecked(first, second, divisor uint64) (uint64, error) {
	if divisor == 0 {
		return 0, errors.New("cost projection overflows")
	}
	if first == 0 || second == 0 {
		return 0, nil
	}
	high, low := bits.Mul64(first, second)
	if high >= divisor {
		return 0, errors.New("cost projection overflows")
	}
	quotient, remainder := bits.Div64(high, low, divisor)
	if remainder == 0 {
		return quotient, nil
	}
	if quotient == math.MaxUint64 {
		return 0, errors.New("cost projection overflows")
	}
	return quotient + 1, nil
}

func mulDivFloor(first, second, divisor uint64) uint64 {
	if divisor == 0 || first == 0 || second == 0 {
		return 0
	}
	high, low := bits.Mul64(first, second)
	if high >= divisor {
		return math.MaxUint64
	}
	quotient, _ := bits.Div64(high, low, divisor)
	return quotient
}

func DecodeBytes(data []byte) (Snapshot, error) {
	return Decode(bytes.NewReader(data))
}

func isUTCTimestamp(ts time.Time) bool {
	if ts.IsZero() {
		return false
	}
	_, offset := ts.Zone()
	return offset == 0
}
