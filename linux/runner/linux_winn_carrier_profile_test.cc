// Carrier-profile tests for the Linux Winn host.
//
// WHY THIS FILE EXISTS. The first version of the Linux carrier profile omitted
// `session_id` entirely. carrierhost.ParseProfile calls
// mobility.ValidSessionID, which refuses anything that is not exactly 32
// lowercase hex characters -- including the empty string -- so EVERY Linux
// http3-connect-udp session would have failed to parse before any network dial.
// Nothing caught it, because nothing tested the document this host emits. The
// bug was found by a reviewer reading this file as a reference implementation
// for the Apple port, which is not a substitute for a test.
//
// It is deliberately free of glib/gio (unlike linux_secure_store_test.cc) so it
// builds and RUNS on the development host as well as on Linux -- the emitted
// document is pure string work, and a test that only the target platform can
// execute is a test that does not get run.

#include "linux_winn_host.h"

#include <sys/stat.h>
#include <unistd.h>

#include <cassert>
#include <cstdlib>
#include <fstream>
#include <iostream>
#include <string>

namespace {

// The six credential files ResolveLinuxWinnCarrierCredentials insists on. Their
// CONTENTS are irrelevant here and deliberately junk: the host must name them
// by path and never open them, so a test that wrote real-looking key material
// would be asserting the opposite of the property under test.
const char* kCredentialFiles[] = {
    "controller_pins.json", "winn_root_ca.pem", "ech_config_list.bin",
    "device_mldsa_seed.bin", "client_cert.pem", "client_key.pem",
    // The knock key. Required only by a session whose served config turns SPA
    // on, which is why the host resolves it separately from the six above --
    // requiring it unconditionally would break every existing carrier profile
    // on a machine that has no knock key, which is every machine today.
    "spa_knock_key.hex",
};

std::string MakeCredentialDirectory() {
  char tmpl[] = "/tmp/wins-winn-carrier-test.XXXXXX";
  const char* root = mkdtemp(tmpl);
  assert(root != nullptr);
  assert(setenv("XDG_DATA_HOME", root, 1) == 0);
  const std::string dir = std::string(root) + "/wins_vpn/winn";
  assert(mkdir((std::string(root) + "/wins_vpn").c_str(), 0700) == 0);
  assert(mkdir(dir.c_str(), 0700) == 0);
  for (const char* name : kCredentialFiles) {
    std::ofstream out(dir + "/" + name);
    out << "not-key-material";
    assert(out.good());
  }
  return dir;
}

// A `[winn]` section naming the fronted carrier, with every required carrier
// key. `session_id` here is the one the SERVER chose -- the whole point of the
// anti-correlation check below is that it must not reach the carrier profile.
constexpr char kServedSessionId[] = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

std::string CarrierConfig() {
  return
      "[Interface]\n"
      "PrivateKey = redacted\n"
      "[Peer]\n"
      "Endpoint = 203.0.113.9:51820\n"
      "[winn]\n"
      "enabled = true\n"
      "endpoint = 203.0.113.9:51820\n"
      "session_id = " + std::string(kServedSessionId) + "\n"
      "carrier = http3-connect-udp\n"
      // WINN_MANDATORY_HEADERS 2026-08-08 (linux_winn_host.cc): h1..h4 are
      // REQUIRED for every session, carrier or direct-awg alike. Four
      // pairwise non-overlapping ranges (not scalars), so this fixture
      // exercises ParseHeaderSpec's range form the way a served config does.
      "h1 = 1000-1999\n"
      "h2 = 2000-2999\n"
      "h3 = 3000-3999\n"
      "h4 = 4000-4999\n"
      "masque_template = https://front.example/.well-known/masque/udp/\n"
      "public_target = 203.0.113.9:443\n"
      "server_name = front.example\n"
      "suite = x25519-mlkem768\n"
      "controller_id = controller-1\n"
      "device_id = device-1\n"
      "device_pq_algorithm = mldsa65\n"
      "manifest_digest = "
      "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\n";
}

std::string FieldValue(const std::string& json, const std::string& key) {
  const std::string needle = "\"" + key + "\":\"";
  const size_t at = json.find(needle);
  if (at == std::string::npos) return "";
  const size_t start = at + needle.size();
  const size_t end = json.find('"', start);
  if (end == std::string::npos) return "";
  return json.substr(start, end - start);
}

bool IsThirtyTwoLowerHex(const std::string& v) {
  if (v.size() != 32) return false;
  for (const char c : v) {
    const bool digit = c >= '0' && c <= '9';
    const bool lower = c >= 'a' && c <= 'f';
    if (!digit && !lower) return false;
  }
  return true;
}

}  // namespace

int main() {
  MakeCredentialDirectory();

  winsvpn::winn::LinuxWinnParams params;
  std::string error;
  const bool parsed =
      winsvpn::winn::ParseLinuxWinnSection(CarrierConfig(), &params, &error);
  if (!parsed) {
    std::cerr << "ParseLinuxWinnSection refused a valid carrier config: "
              << error << "\n";
    return 1;
  }
  assert(params.has_carrier_profile);
  assert(params.carrier == "http3-connect-udp");

  const std::string profile_json =
      winsvpn::winn::BuildLinuxWinnCarrierProfileJson(params.carrier_profile);

  // 1. The field exists and satisfies mobility.ValidSessionID. Its absence is
  // the original bug: carrierhost refuses an empty session_id outright, so this
  // failing means no Linux carrier session can start at all.
  const std::string profile_session = FieldValue(profile_json, "session_id");
  assert(IsThirtyTwoLowerHex(profile_session));

  // 2. THE ANTI-CORRELATION PROPERTY. The carrier profile's session id must not
  // be the one the control plane served, because the carrier operator would
  // then be able to link the session to the account that fetched the config.
  // WinnCarrierProfile.kt documents this as a deliberate choice rather than an
  // oversight, and reusing params.session_id here would silently undo it.
  assert(params.session_id == kServedSessionId);
  assert(profile_session != params.session_id);

  // 3. It is FRESH PER SESSION, not merely different from the served one. A
  // constant would pass checks 1 and 2 and still correlate every session this
  // device ever opens.
  winsvpn::winn::LinuxWinnParams second;
  assert(winsvpn::winn::ParseLinuxWinnSection(CarrierConfig(), &second, &error));
  const std::string second_session = FieldValue(
      winsvpn::winn::BuildLinuxWinnCarrierProfileJson(second.carrier_profile),
      "session_id");
  assert(IsThirtyTwoLowerHex(second_session));
  assert(second_session != profile_session);

  // 4. Field order matches Kotlin/Swift: session_id sits immediately after
  // client_key_path. The documents are compared byte for byte in review, so a
  // reordering is a real divergence even though JSON does not care.
  const size_t key_at = profile_json.find("\"client_key_path\"");
  const size_t session_at = profile_json.find("\"session_id\"");
  assert(key_at != std::string::npos && session_at != std::string::npos);
  assert(key_at < session_at);

  // 5. NO KEY MATERIAL crossed into the document -- only paths. The credential
  // files were filled with a marker string precisely so this can be asserted.
  assert(profile_json.find("not-key-material") == std::string::npos);
  assert(profile_json.find("PrivateKey") == std::string::npos);

  // 6. The base datapath.Config still carries the SERVED session id. The two
  // documents are different documents with different audiences; fixing one must
  // not have quietly changed the other.
  const std::string config_json =
      winsvpn::winn::BuildLinuxWinnConfigJson(params);
  assert(FieldValue(config_json, "session_id") == kServedSessionId);

  // 7. SPA OFF EMITS NOTHING. Absence is the contract, not tidiness -- but be
  // exact about the reason. carrierhost REFUSES a document carrying a
  // NON-EMPTY spa_ field while the mode is off (ErrSPAFieldWithoutMode); an
  // emitter that wrote "spa_mode":"off" or "spa_target":"" would NOT break
  // non-SPA Linux sessions, because the stray sweep tests TrimSpace(...) != ""
  // and != 0, so those parse fine. (An earlier comment here claimed the
  // opposite; it was checked against ParseProfile and is false.) The assertion
  // below is still the right one: no spa_ substring anywhere is a contract a
  // reader can check without modelling which empty values are forgiven, and it
  // makes the one shape that IS a hard refusal -- a non-empty stray --
  // unreachable from this emitter.
  assert(!params.carrier_profile.spa_required);
  assert(profile_json.find("spa_") == std::string::npos);

  // 8. SPA ON SURVIVES THE EMITTER. The five served knock parameters reach the
  // document with the values the config carried, plus the device-local key
  // path the host resolved itself.
  winsvpn::winn::LinuxWinnParams spa_params;
  const std::string spa_config =
      CarrierConfig() +
      "spa_mode = required\n"
      "spa_target = 203.0.113.9:9111\n"
      "spa_packet_size = 256\n"
      "spa_bucket_window_seconds = 10\n"
      "spa_max_skew_seconds = 60\n";
  if (!winsvpn::winn::ParseLinuxWinnSection(spa_config, &spa_params, &error)) {
    std::cerr << "ParseLinuxWinnSection refused a valid SPA config: " << error
              << "\n";
    return 1;
  }
  assert(spa_params.carrier_profile.spa_required);
  const std::string spa_json = winsvpn::winn::BuildLinuxWinnCarrierProfileJson(
      spa_params.carrier_profile);
  assert(FieldValue(spa_json, "spa_mode") == "required");
  assert(FieldValue(spa_json, "spa_target") == "203.0.113.9:9111");
  assert(spa_json.find("\"spa_packet_size\":256") != std::string::npos);
  assert(spa_json.find("\"spa_bucket_window_seconds\":10") !=
         std::string::npos);
  assert(spa_json.find("\"spa_max_skew_seconds\":60") != std::string::npos);

  // 9. THE KEY IS NAMED BY PATH AND ITS CONTENTS NEVER APPEAR. The fixture file
  // is filled with a marker string precisely so the second half is assertable
  // rather than merely intended.
  const std::string spa_key_path = FieldValue(spa_json, "spa_key_path");
  assert(spa_key_path.find("spa_knock_key.hex") != std::string::npos);
  assert(spa_json.find("not-key-material") == std::string::npos);

  // 10. THE LOG LINE NAMES THE MODE AND NOTHING ELSE. Neither the key path nor
  // the knock target may reach a log: the target names a host that is supposed
  // to be invisible, which is the entire point of gating it.
  const std::string described =
      winsvpn::winn::DescribeLinuxWinnCarrierProfile(spa_params.carrier_profile);
  assert(described.find("spa=required") != std::string::npos);
  assert(described.find("203.0.113.9:9111") == std::string::npos);
  assert(described.find("spa_knock_key") == std::string::npos);

  // 11. A STRAY spa_ FIELD WITHOUT THE MODE IS A REFUSAL, not a silent drop.
  // This is the failure mode that made SPA unreachable in the first place:
  // every host quietly discarded a key it did not recognise.
  winsvpn::winn::LinuxWinnParams stray_params;
  std::string stray_error;
  const bool stray_ok = winsvpn::winn::ParseLinuxWinnSection(
      CarrierConfig() + "spa_target = 203.0.113.9:9111\n", &stray_params,
      &stray_error);
  assert(!stray_ok);
  assert(stray_error.find("spa_target") != std::string::npos);

  // 12. AN UNKNOWN spa_mode IS A REFUSAL. Anything but off/required means this
  // build does not implement what the server asked for.
  winsvpn::winn::LinuxWinnParams bad_mode;
  std::string bad_mode_error;
  assert(!winsvpn::winn::ParseLinuxWinnSection(
      CarrierConfig() + "spa_mode = advisory\nspa_target = 203.0.113.9:9111\n",
      &bad_mode, &bad_mode_error));
  assert(bad_mode_error.find("spa_mode") != std::string::npos);

  // 13. spa_target IS REQUIRED AND MUST BE AN IP LITERAL. There is deliberately
  // no default: the gate may sit in front of the carrier listener or in front
  // of the AmneziaWG gateway, and a wrong guess sends the deployment's shared
  // credential to a host that is not supposed to have it.
  for (const char* bad_target : {"", "gate.example:9111", "203.0.113.9"}) {
    winsvpn::winn::LinuxWinnParams bad;
    std::string bad_error;
    const std::string line =
        std::string("spa_mode = required\nspa_target = ") + bad_target + "\n";
    assert(!winsvpn::winn::ParseLinuxWinnSection(CarrierConfig() + line, &bad,
                                                 &bad_error));
    assert(bad_error.find("spa_target") != std::string::npos);
  }

  std::cout << "linux winn carrier profile: 13/13 checks passed\n"
            << "  profile session_id  = " << profile_session << "\n"
            << "  second run          = " << second_session << " (differs)\n"
            << "  served/config id    = " << kServedSessionId << " (unchanged)\n"
            << "  spa off             = no spa_ key in the document\n"
            << "  spa on              = mode+target+3 scalars survived, key by path\n";
  return 0;
}
