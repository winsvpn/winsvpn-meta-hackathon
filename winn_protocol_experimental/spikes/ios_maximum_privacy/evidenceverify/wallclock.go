package main

// Wall-clock field validation.
//
// WHAT THIS PROVES, AND WHAT IT CANNOT.
//
// Every record carries two independently sampled clocks: a monotonic counter
// and a UTC wall time. This file requires the wall time to be canonically
// spelled, to be non-decreasing across the run, and to advance at
// approximately the rate the monotonic counter advanced.
//
// That is an INTERNAL CONSISTENCY check between two clocks the SAME process
// read. It is not, and cannot be, evidence that the wall clock was correct:
// nothing here observes an independent time source, and a device whose clock
// is uniformly wrong — or was deliberately set — produces evidence that passes
// every check below. What it does refuse is a record set whose wall times were
// filled in without reference to the run that actually happened: constant
// timestamps across a long run, a reordered or back-dated line, a
// non-canonical spelling that two readers would parse differently, and a wall
// span that disagrees with the measured monotonic span.

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
)

const (
	// canonicalWallSecondsLayout is the seconds-resolution prefix. The zone is
	// handled separately because only a literal `Z` is accepted: an offset
	// spelling such as `+00:00` denotes the same instant but is a different
	// document, and evidence bytes are hashed.
	canonicalWallSecondsLayout = "2006-01-02T15:04:05"

	// Plausibility bounds. These keep every later subtraction inside int64
	// nanoseconds and refuse timestamps no Stage A run could carry. They are
	// bounds on this spike's evidence, not claims about the device's clock.
	minimumWallYear = 2020
	maximumWallYear = 2100

	// The longest selectable run is eight hours. Thirty days is a deliberately
	// loose ceiling that still keeps nanosecond arithmetic well inside int64.
	maximumRunSpanNanoseconds = 30 * 24 * 60 * 60 * 1_000_000_000

	// Allowed disagreement between the wall and monotonic deltas: a fixed
	// allowance for sampling the two clocks at slightly different moments,
	// plus a proportional allowance for genuine drift and for a clock
	// correction landing inside a long run.
	wallSkewFixedNanoseconds      = 5_000_000_000
	wallSkewProportionalDivisor   = 200
	wallClockConsistencyStatement = "wall and monotonic clocks disagree"
)

// parseCanonicalWallTime accepts exactly `YYYY-MM-DDTHH:MM:SS[.f{1,9}]Z` and
// nothing else.
//
// HOW THE SPELLING IS ACTUALLY PINNED, since the mechanism is not obvious.
// time.Parse on its own is too lenient — several of its numeric fields accept
// one digit where two are canonical. What removes that freedom here is the
// FIXED-WIDTH SPLIT: the seconds portion is taken as exactly the first 19
// bytes, the zone as exactly the last byte, and the separator between the
// seconds and any fraction must be a '.' at exactly offset 19. An unpadded
// month or a one-digit hour shifts every later byte, so the split itself, the
// '.' position, or time.Parse's literal matching refuses it.
//
// An earlier draft also re-rendered the parsed instant and compared it with
// the input. Mutation testing showed that comparison never fires: with the
// width already fixed there is no accepted-but-differently-spelled value left
// for it to catch. It was removed rather than kept as a check that looks like
// it is doing work it is not.
func parseCanonicalWallTime(value string) (time.Time, error) {
	if len(value) < len("2006-01-02T15:04:05Z") {
		return time.Time{}, errors.New(
			"wall time is shorter than a seconds-resolution UTC instant",
		)
	}
	if value[len(value)-1] != 'Z' {
		return time.Time{}, errors.New(
			"wall time does not end in a literal UTC 'Z'",
		)
	}
	body := value[:len(value)-1]
	seconds := body
	fraction := ""
	if len(body) > len(canonicalWallSecondsLayout) {
		if body[len(canonicalWallSecondsLayout)] != '.' {
			return time.Time{}, errors.New(
				"wall time has no '.' before its fractional seconds",
			)
		}
		seconds = body[:len(canonicalWallSecondsLayout)]
		fraction = body[len(canonicalWallSecondsLayout)+1:]
		if len(fraction) < 1 || len(fraction) > 9 {
			return time.Time{}, errors.New(
				"wall time fraction must be 1 to 9 digits",
			)
		}
		for index := 0; index < len(fraction); index++ {
			if fraction[index] < '0' || fraction[index] > '9' {
				return time.Time{}, errors.New(
					"wall time fraction is not decimal digits",
				)
			}
		}
	}
	parsed, err := time.Parse(canonicalWallSecondsLayout, seconds)
	if err != nil {
		return time.Time{}, fmt.Errorf("wall time is not RFC 3339: %w", err)
	}
	if fraction != "" {
		padded := fraction + strings.Repeat("0", 9-len(fraction))
		nanoseconds, err := strconv.ParseInt(padded, 10, 64)
		if err != nil {
			return time.Time{}, errors.New("wall time fraction is invalid")
		}
		parsed = parsed.Add(time.Duration(nanoseconds))
	}
	if parsed.Year() < minimumWallYear || parsed.Year() >= maximumWallYear {
		return time.Time{}, fmt.Errorf(
			"wall time year %d is outside [%d, %d)",
			parsed.Year(),
			minimumWallYear,
			maximumWallYear,
		)
	}
	return parsed.UTC(), nil
}

// verifyWallClock checks presence, canonical spelling, ordering, and
// wall-versus-monotonic consistency across a run's records.
//
// Callers have already established that MonotonicNanoseconds is strictly
// increasing, so the monotonic delta is the reference and the wall delta is
// the value under test.
func verifyWallClock(records []metricRecord) error {
	walls := make([]time.Time, len(records))
	for index, record := range records {
		parsed, err := parseCanonicalWallTime(record.WallTimeUTC)
		if err != nil {
			return fmt.Errorf("record %d: %w", index+1, err)
		}
		walls[index] = parsed
	}
	for index := 1; index < len(records); index++ {
		if walls[index].Before(walls[index-1]) {
			return fmt.Errorf(
				"record %d wall time moves backwards", index+1,
			)
		}
		if err := requireWallMatchesMonotonic(
			walls[index-1],
			walls[index],
			records[index-1].MonotonicNanoseconds,
			records[index].MonotonicNanoseconds,
			fmt.Sprintf("records %d to %d", index, index+1),
		); err != nil {
			return err
		}
	}
	if len(records) < 2 {
		return nil
	}
	// The adjacent checks each carry their own fixed allowance, so a long run
	// could accumulate many small consistent-looking steps. The whole-run
	// comparison bounds the total independently.
	return requireWallMatchesMonotonic(
		walls[0],
		walls[len(walls)-1],
		records[0].MonotonicNanoseconds,
		records[len(records)-1].MonotonicNanoseconds,
		"the whole run",
	)
}

func requireWallMatchesMonotonic(
	earlierWall time.Time,
	laterWall time.Time,
	earlierMonotonic uint64,
	laterMonotonic uint64,
	name string,
) error {
	monotonicSpan := laterMonotonic - earlierMonotonic
	if monotonicSpan > maximumRunSpanNanoseconds {
		return fmt.Errorf(
			"%s span %d ns exceeds the %d ns evidence ceiling",
			name,
			monotonicSpan,
			uint64(maximumRunSpanNanoseconds),
		)
	}
	wallSpan := laterWall.Sub(earlierWall)
	if wallSpan > maximumRunSpanNanoseconds {
		return fmt.Errorf(
			"%s wall span exceeds the %d ns evidence ceiling",
			name,
			uint64(maximumRunSpanNanoseconds),
		)
	}
	// #nosec G115 -- monotonicSpan was bounded by the ceiling above, which is
	// far below math.MaxInt64.
	difference := wallSpan - time.Duration(int64(monotonicSpan))
	if difference < 0 {
		difference = -difference
	}
	allowed := time.Duration(
		wallSkewFixedNanoseconds +
			int64(monotonicSpan)/wallSkewProportionalDivisor,
	)
	if difference > allowed {
		return fmt.Errorf(
			"%s: %s by %s against a %s allowance",
			name,
			wallClockConsistencyStatement,
			difference,
			allowed,
		)
	}
	return nil
}
