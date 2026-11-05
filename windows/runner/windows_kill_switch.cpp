#include "windows_kill_switch.h"

#include <fwpmu.h>

#include <cstring>

namespace {

const GUID kKsProvider = {0x6a1c9b4e, 0x0f7d, 0x4c53,
                          {0x9a, 0x0b, 0x3e, 0x2d, 0x51, 0xc7, 0xa9, 0x01}};
const GUID kKsSublayer = {0x6a1c9b4e, 0x0f7d, 0x4c53,
                          {0x9a, 0x0b, 0x3e, 0x2d, 0x51, 0xc7, 0xa9, 0x02}};
const GUID* const kKsLayers[] = {
    &FWPM_LAYER_ALE_AUTH_CONNECT_V4, &FWPM_LAYER_ALE_AUTH_CONNECT_V6,
    &FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4, &FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6};

bool IsV6(const GUID& layer) {
  return IsEqualGUID(layer, FWPM_LAYER_ALE_AUTH_CONNECT_V6) ||
         IsEqualGUID(layer, FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6);
}

bool AddKsFilter(HANDLE engine, const GUID& layer, FWP_ACTION_TYPE action,
                 UINT8 weight, FWPM_FILTER_CONDITION0* conditions,
                 UINT32 count) {
  FWPM_FILTER0 filter = {};
  wchar_t name[] = L"Win's VPN network policy";
  filter.displayData.name = name;
  filter.providerKey = const_cast<GUID*>(&kKsProvider);
  filter.layerKey = layer;
  filter.subLayerKey = kKsSublayer;
  filter.weight.type = FWP_UINT8;
  filter.weight.uint8 = weight;
  filter.action.type = action;
  filter.numFilterConditions = count;
  filter.filterCondition = count == 0 ? nullptr : conditions;
  return FwpmFilterAdd0(engine, &filter, nullptr, nullptr) == ERROR_SUCCESS;
}

// Enumerates every filter (no template, so no enum-type semantics are
// involved), keeps the ids in this sublayer, closes the enumeration, then
// deletes them.
bool DeleteOwnedFilters(HANDLE engine) {
  HANDLE enumeration = nullptr;
  if (FwpmFilterCreateEnumHandle0(engine, nullptr, &enumeration) !=
      ERROR_SUCCESS) {
    return false;
  }
  std::vector<UINT64> owned;
  bool ok = true;
  for (;;) {
    FWPM_FILTER0** entries = nullptr;
    UINT32 count = 0;
    if (FwpmFilterEnum0(engine, enumeration, 256, &entries, &count) !=
        ERROR_SUCCESS) {
      ok = false;
      break;
    }
    for (UINT32 i = 0; i < count; ++i) {
      if (IsEqualGUID(entries[i]->subLayerKey, kKsSublayer)) {
        owned.push_back(entries[i]->filterId);
      }
    }
    if (entries != nullptr) {
      FwpmFreeMemory0(reinterpret_cast<void**>(&entries));
    }
    if (count == 0) break;
  }
  FwpmFilterDestroyEnumHandle0(engine, enumeration);
  if (!ok) return false;
  for (const UINT64 id : owned) {
    const DWORD status = FwpmFilterDeleteById0(engine, id);
    if (status != ERROR_SUCCESS &&
        status != static_cast<DWORD>(FWP_E_FILTER_NOT_FOUND)) {
      return false;
    }
  }
  return true;
}

bool EnsureProviderAndSublayer(HANDLE engine) {
  FWPM_PROVIDER0* existing_provider = nullptr;
  if (FwpmProviderGetByKey0(engine, &kKsProvider, &existing_provider) ==
      ERROR_SUCCESS) {
    FwpmFreeMemory0(reinterpret_cast<void**>(&existing_provider));
  } else {
    FWPM_PROVIDER0 provider = {};
    wchar_t pname[] = L"Win's VPN";
    provider.providerKey = kKsProvider;
    provider.displayData.name = pname;
    if (FwpmProviderAdd0(engine, &provider, nullptr) != ERROR_SUCCESS) {
      return false;
    }
  }
  FWPM_SUBLAYER0* existing_sublayer = nullptr;
  if (FwpmSubLayerGetByKey0(engine, &kKsSublayer, &existing_sublayer) ==
      ERROR_SUCCESS) {
    FwpmFreeMemory0(reinterpret_cast<void**>(&existing_sublayer));
    return true;
  }
  FWPM_SUBLAYER0 sublayer = {};
  wchar_t sname[] = L"Win's VPN network policy";
  sublayer.subLayerKey = kKsSublayer;
  sublayer.displayData.name = sname;
  sublayer.providerKey = const_cast<GUID*>(&kKsProvider);
  sublayer.weight = 0xFFFF;
  return FwpmSubLayerAdd0(engine, &sublayer, nullptr) == ERROR_SUCCESS;
}

bool OpenEngine(HANDLE* engine) {
  FWPM_SESSION0 session = {};  // flags 0: NOT dynamic, outlives this process
  return FwpmEngineOpen0(nullptr, RPC_C_AUTHN_WINNT, nullptr, &session,
                         engine) == ERROR_SUCCESS;
}

}  // namespace

bool WindowsPermitPrefixFromEndpoint(const std::string& endpoint,
                                     IP_ADDRESS_PREFIX* out) {
  if (out == nullptr) return false;
  *out = IP_ADDRESS_PREFIX{};
  std::string host;
  if (!endpoint.empty() && endpoint.front() == '[') {
    const size_t close = endpoint.find(']');
    if (close == std::string::npos || close < 2) return false;
    host = endpoint.substr(1, close - 1);
  } else {
    const size_t colon = endpoint.rfind(':');
    if (colon == std::string::npos || colon == 0) return false;
    host = endpoint.substr(0, colon);
  }
  if (InetPtonA(AF_INET, host.c_str(), &out->Prefix.Ipv4.sin_addr) == 1) {
    out->Prefix.si_family = AF_INET;
    out->PrefixLength = 32;
    return true;
  }
  if (InetPtonA(AF_INET6, host.c_str(), &out->Prefix.Ipv6.sin6_addr) == 1) {
    out->Prefix.si_family = AF_INET6;
    out->PrefixLength = 128;
    return true;
  }
  *out = IP_ADDRESS_PREFIX{};
  return false;
}

bool EnableWindowsKillSwitch(const NET_LUID& tunnel_luid,
                             const std::vector<IP_ADDRESS_PREFIX>& permitted_remote,
                             std::string* error) {
  HANDLE engine = nullptr;
  if (!OpenEngine(&engine)) {
    *error = "Unable to open the Windows filtering engine.";
    return false;
  }
  bool ok = FwpmTransactionBegin0(engine, 0) == ERROR_SUCCESS;
  ok = ok && EnsureProviderAndSublayer(engine);
  ok = ok && DeleteOwnedFilters(engine);
  for (const GUID* layer_ptr : kKsLayers) {
    if (!ok) break;
    const GUID& layer = *layer_ptr;
    const bool v6 = IsV6(layer);
    // 1. Loopback.
    FWPM_FILTER_CONDITION0 loopback = {};
    loopback.fieldKey = FWPM_CONDITION_FLAGS;
    loopback.matchType = FWP_MATCH_FLAGS_ALL_SET;
    loopback.conditionValue.type = FWP_UINT32;
    loopback.conditionValue.uint32 = FWP_CONDITION_FLAG_IS_LOOPBACK;
    ok = AddKsFilter(engine, layer, FWP_ACTION_PERMIT, 15, &loopback, 1);
    // 2. The tunnel adapter.
    UINT64 luid = tunnel_luid.Value;
    if (ok && luid != 0) {
      FWPM_FILTER_CONDITION0 tunnel = {};
      tunnel.fieldKey = FWPM_CONDITION_IP_LOCAL_INTERFACE;
      tunnel.matchType = FWP_MATCH_EQUAL;
      tunnel.conditionValue.type = FWP_UINT64;
      tunnel.conditionValue.uint64 = &luid;
      ok = AddKsFilter(engine, layer, FWP_ACTION_PERMIT, 14, &tunnel, 1);
    }
    // 3. DHCP (v4 68 to 67, v6 546 to 547).
    if (ok) {
      FWPM_FILTER_CONDITION0 dhcp[3] = {};
      dhcp[0].fieldKey = FWPM_CONDITION_IP_PROTOCOL;
      dhcp[0].matchType = FWP_MATCH_EQUAL;
      dhcp[0].conditionValue.type = FWP_UINT8;
      dhcp[0].conditionValue.uint8 = IPPROTO_UDP;
      dhcp[1].fieldKey = FWPM_CONDITION_IP_LOCAL_PORT;
      dhcp[1].matchType = FWP_MATCH_EQUAL;
      dhcp[1].conditionValue.type = FWP_UINT16;
      dhcp[1].conditionValue.uint16 = v6 ? 546 : 68;
      dhcp[2].fieldKey = FWPM_CONDITION_IP_REMOTE_PORT;
      dhcp[2].matchType = FWP_MATCH_EQUAL;
      dhcp[2].conditionValue.type = FWP_UINT16;
      dhcp[2].conditionValue.uint16 = v6 ? 547 : 67;
      ok = AddKsFilter(engine, layer, FWP_ACTION_PERMIT, 13, dhcp, 3);
    }
    // 3b. IPv6 Neighbor Discovery. The ALE layers classify ICMPv6 too, so
    // the weight-0 block below would also drop the host's own router and
    // neighbor solicitations and the router's advertisements, and an IPv6
    // carrier endpoint (permitted as a /128 in step 4) could never resolve
    // its next hop. Same exception the Linux block carries
    // (append_ipv6_link_control) and that wireguard-windows installs
    // (firewall/rules.go permitNdp): types 133 to 137, code 0, both
    // directions. Protocol 58 is ICMPv6.
    if (ok && v6) {
      // int, not UINT16: the runner builds with /W4 /WX and an implicit
      // narrowing in the range declaration is C4244.
      for (const int icmp_type : {133, 134, 135, 136, 137}) {
        if (!ok) break;
        FWPM_FILTER_CONDITION0 ndp[3] = {};
        ndp[0].fieldKey = FWPM_CONDITION_IP_PROTOCOL;
        ndp[0].matchType = FWP_MATCH_EQUAL;
        ndp[0].conditionValue.type = FWP_UINT8;
        ndp[0].conditionValue.uint8 = 58;
        ndp[1].fieldKey = FWPM_CONDITION_ICMP_TYPE;
        ndp[1].matchType = FWP_MATCH_EQUAL;
        ndp[1].conditionValue.type = FWP_UINT16;
        ndp[1].conditionValue.uint16 = static_cast<UINT16>(icmp_type);
        ndp[2].fieldKey = FWPM_CONDITION_ICMP_CODE;
        ndp[2].matchType = FWP_MATCH_EQUAL;
        ndp[2].conditionValue.type = FWP_UINT16;
        ndp[2].conditionValue.uint16 = 0;
        ok = AddKsFilter(engine, layer, FWP_ACTION_PERMIT, 13, ndp, 3);
      }
    }
    // 4. Each permitted remote prefix of this family. These exceptions
    // permit every application, protocol and port addressing the prefix.
    // Plaintext payloads sent to a carrier address can leave off tunnel.
    // Intentional destination splits need separate provenance.
    for (const IP_ADDRESS_PREFIX& prefix : permitted_remote) {
      if (!ok) break;
      if ((prefix.Prefix.si_family == AF_INET6) != v6) continue;
      if (prefix.PrefixLength == 0) continue;  // never a permit-all
      FWPM_FILTER_CONDITION0 remote = {};
      remote.fieldKey = FWPM_CONDITION_IP_REMOTE_ADDRESS;
      remote.matchType = FWP_MATCH_EQUAL;
      FWP_V4_ADDR_AND_MASK v4mask = {};
      FWP_V6_ADDR_AND_MASK v6mask = {};
      if (v6) {
        std::memcpy(v6mask.addr, &prefix.Prefix.Ipv6.sin6_addr, 16);
        v6mask.prefixLength = prefix.PrefixLength;
        remote.conditionValue.type = FWP_V6_ADDR_MASK;
        remote.conditionValue.v6AddrMask = &v6mask;
      } else {
        v4mask.addr = ntohl(prefix.Prefix.Ipv4.sin_addr.s_addr);
        v4mask.mask = 0xFFFFFFFFu << (32 - prefix.PrefixLength);
        remote.conditionValue.type = FWP_V4_ADDR_MASK;
        remote.conditionValue.v4AddrMask = &v4mask;
      }
      ok = AddKsFilter(engine, layer, FWP_ACTION_PERMIT, 12, &remote, 1);
    }
    // 5. Everything else.
    if (ok) ok = AddKsFilter(engine, layer, FWP_ACTION_BLOCK, 0, nullptr, 0);
  }
  if (ok) {
    ok = FwpmTransactionCommit0(engine) == ERROR_SUCCESS;
  } else {
    FwpmTransactionAbort0(engine);
  }
  FwpmEngineClose0(engine);
  if (!ok) *error = "Windows refused the tunnel network policy.";
  return ok;
}

bool DisableWindowsKillSwitch(std::string* error) {
  HANDLE engine = nullptr;
  if (!OpenEngine(&engine)) {
    *error = "Unable to open the Windows filtering engine.";
    return false;
  }
  bool ok = FwpmTransactionBegin0(engine, 0) == ERROR_SUCCESS &&
            DeleteOwnedFilters(engine);
  if (ok) {
    const DWORD s = FwpmSubLayerDeleteByKey0(engine, &kKsSublayer);
    ok = s == ERROR_SUCCESS ||
         s == static_cast<DWORD>(FWP_E_SUBLAYER_NOT_FOUND);
  }
  if (ok) {
    const DWORD p = FwpmProviderDeleteByKey0(engine, &kKsProvider);
    ok = p == ERROR_SUCCESS ||
         p == static_cast<DWORD>(FWP_E_PROVIDER_NOT_FOUND);
  }
  if (ok) {
    ok = FwpmTransactionCommit0(engine) == ERROR_SUCCESS;
  } else {
    FwpmTransactionAbort0(engine);
  }
  FwpmEngineClose0(engine);
  if (!ok) *error = "Windows could not remove the tunnel network policy.";
  return ok;
}
