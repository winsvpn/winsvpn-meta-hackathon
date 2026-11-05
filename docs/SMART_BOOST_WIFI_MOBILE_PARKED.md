# Smart Boost / Wi-Fi + Mobile Data Parked State

Last parked: 2026-07-02

This note preserves the Wi-Fi + Mobile Data development progress while the public app release returns to the stable Winn Protocol path.

## Why Parked

- Direct Winn Protocol / AmneziaWG is currently faster and more stable on the live Android phone and LA data plane.
- The Kotlin userspace Smart Boost path proved that Wi-Fi and cellular sockets can be opened and bound, but it did not beat direct AWG in real phone tests.
- The public release should not expose a mode that can feel slower or experimental.

## Last Working Safety State

- Data-plane daemon version: `v8.15-cellular-proof-safe-batch`.
- Android proof: fresh uninstall/install on USB phone `365c61de`, free activation, legal clickwrap, VPN permission, notification permission, and LA egress all passed.
- Public IPv4 during test: `<HISTORICAL_NODE_IP>`.
- Bounded Sonic LA comparison from the same development pass:
  - Direct Winn Protocol / AWG median: `128.8 Mbps`.
  - Smart Boost v8.14 median: `78.6 Mbps`.
- Result: Smart Boost correctly fell back to Winn Protocol instead of staying active.
- APK hash for the final safe-gated Smart Boost build before parking: `D6E3CB1E8DAD6F46F4DB061A7B3374FA0BF8B59228E23288F0600CBA6331D8F1`.

## Parked Code Areas

- `server/wins_boostd_v2.go`
- Embedded daemon in `server/wins_data_plane_setup_ONETOUCH.sh`
- Android native/Kotlin experimental files:
  - `docs/parked_smart_boost/VpnTunnelService_with_smart_boost.kt.disabled`
  - `docs/parked_smart_boost/SmartBoostNative.kt.disabled`
  - `docs/parked_smart_boost/android_cpp/smart_boost_native.cpp`
  - `docs/parked_smart_boost/android_cpp/CMakeLists.txt`
- Phone benchmark tools:
  - `tools/smart_boost_phone_benchmark.ps1`
  - `tools/smart_boost_qualify.ps1`

## Release Cut

For the stable public app:

- The Flutter UI no longer shows Wi-Fi + Mobile Data.
- The app no longer saves `wifi_mobile_data_enabled`.
- The app no longer sends a `[WinsBoost]` section to Android.
- The app no longer calls Smart Boost status or qualification.
- The Android service strips stale `[WinsBoost]` sections defensively but does not parse, select, or start Smart Boost.
- The experimental Kotlin engine and native bridge were moved out of compiled Android source into `docs/parked_smart_boost/`.
- Android no longer builds the experimental `winsboostnative` C++ library.
- Stable Android release APK after parking and Double VPN lockout: `CE124D4D94428BE4AC73D12691EFD3CFB282967752EDDA60D59ABDAE8947485B`.

## Resume Criteria

Resume this feature only after building a true native packet engine:

- Native TUN read/write loop.
- Native UDP socket loop with Wi-Fi and cellular bindings.
- Audited native crypto path.
- Packet batching without Android/Dart/Kotlin per-packet overhead.
- Per-path congestion control, loss handling, reordering, MTU handling, and failover.
- Real phone benchmark must beat direct AWG on the same server, same phone, same network window.
- Single-flow and multi-flow tests must both pass before marketing it as Speedify-class.
