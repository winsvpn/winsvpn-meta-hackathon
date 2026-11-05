//go:build !linux && !android

package carrier

// gsoTxStats is the GSO wrapper's counter fill on the platforms that have no
// UDP_SEGMENT: every field stays zero, which is the honest report.
func (u *UDP) gsoTxStats(*Stats) {}
