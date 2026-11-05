# Test image for the SPA integration test. Built once and then served from
# Docker's layer cache, so the test does not depend on the Alpine package
# mirror being reachable on every run -- a transient apk failure was otherwise
# indistinguishable from a real test failure.
FROM alpine:3.20
RUN apk add --no-cache nftables bash
