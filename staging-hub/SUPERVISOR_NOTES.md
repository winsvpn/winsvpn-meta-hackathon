SUPERVISOR NOTE (read me before finalizing router consult code):
Gemini API minimum deadline is 10s. Real decisions return in ~4s.
Set the hub's router-consult HTTP timeout to 12 seconds (not 2s).
Fail-open order unchanged: router unreachable/slow/malformed -> deterministic pick locally.
