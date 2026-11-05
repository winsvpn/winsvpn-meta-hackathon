//go:build !race

package carrier

func raceEnabled() bool { return false }
