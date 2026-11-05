// Deliberately its own module with no requires: the framing conformance fixture
// is standard-library only, so it can be cross-compiled for windows/amd64 and
// windows/arm64 -- and, more importantly, RUN ON THE DEVELOPMENT HOST -- without
// touching the repo's module graph or its pinned dependency set.
//
// Running on the host is the point. The C++ framing self-test in
// windows/runner/winn_frame_selftest.h is header-only and platform-free for the
// same reason, so tools/verify_winn_framing_conformance.sh can check both
// implementations against one byte-exact vector on a machine with no Windows.
module winsvpn.local/winnframingfixture

go 1.27.1
