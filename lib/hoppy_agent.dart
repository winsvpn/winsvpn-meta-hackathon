// Hoppy agent security core: action schema and policy engine.
// Location: source/wins_vpn/lib/hoppy_agent/
// Reasoning: this is a library with no Flutter dependency, placed where the
// control plane can import it as package:wins_vpn/hoppy_agent/... The
// control plane endpoints that Tier 1 actions call will import the engine
// to authorise every request. This keeps the model outside the trust
// boundary: the model proposes a HoppyActionRequest, the engine disposes.
// It is not placed in any server script; it is a versioned library with
// its own tests that the control plane depends on.
//
// Schema file: hoppy_agent/hoppy_action_schema.dart
// Engine file: hoppy_agent/hoppy_policy_engine.dart

export 'hoppy_agent/hoppy_action_schema.dart';
export 'hoppy_agent/hoppy_policy_engine.dart';
export 'hoppy_agent/hoppy_corpus_gate.dart';
export 'hoppy_agent/hoppy_agent_runner.dart';
