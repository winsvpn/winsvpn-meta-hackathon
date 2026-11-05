# Winn v3 descriptor verification ring for Windows flutter_assemble.
# Public keys only. Appended onto Flutter DART_DEFINES so tool_backend.dart
# passes --DartDefines into `flutter assemble` (Flutter 3.44.8
# packages/flutter_tools/bin/tool_backend.dart).
#
# Encoding matches Flutter encodeDartDefines: UTF-8 NAME=VALUE, standard
# base64, comma-joined (packages/flutter_tools/lib/src/build_info.dart).
# Ring identity is WIRE-FORM sha256 of "g1=<hex>\ng2=<hex>\ng3=<hex>\n":
#   52e91c72ca52d23059724e0a6c25c2f45bae574a85a84c884c5b7fd367cbf032
# Do not compile the ceremony MANIFEST digest
#   29c66c18f5aef6eb064e065a5d7c3c98aa1548f758ac6d19b19a9d4a7863e7fb
# as WINS_WINN3_DESCRIPTOR_RING_SHA256.
#
# WINS_WINN3_ENABLED_PLATFORMS=windows is appended only for Release
# (see winn3_tool_backend.cmd). Debug/Profile compile the ring without
# turning standalone v3 on.
#
# Dual-signature gate: base64("WINS_WINN3_DUAL_AUTH=true") rides the same
# Release-only blob. The Windows served [winn] parser consumes auth_ed25519 /
# auth_mldsa65 and binds both paths into the engine document; cmd/winn-datapath
# ingests them. Putting this blob in WINN3_RING_DART_DEFINES would compile it
# into Debug/Profile.

set(WINN3_RING_DART_DEFINES "V0lOU19XSU5OM19ERVNDUklQVE9SX1BVQktFWV9HMT1MMm1BWWRZSVhQQ0Z1Tm9INW50Z0JCdWJGU25ubHpJQW5Yd0t0dHBlaGFRPQ==,V0lOU19XSU5OM19ERVNDUklQVE9SX1BVQktFWV9HMj1lVkNBSFdYcVVNMSttNW5sVnkySlIrUTQvbWtZR1R4bGsxMTlhaVFoODlNPQ==,V0lOU19XSU5OM19ERVNDUklQVE9SX1BVQktFWV9HMz01M0poc1FCeEtINURHMTQ1TGNhQnVuT1g0bGJ0K0o3SnMwb1B5Sm5qOVEwPQ==,V0lOU19XSU5OM19ERVNDUklQVE9SX1JJTkdfU0hBMjU2PTUyZTkxYzcyY2E1MmQyMzA1OTcyNGUwYTZjMjVjMmY0NWJhZTU3NGE4NWE4NGM4ODRjNWI3ZmQzNjdjYmYwMzI=")
set(WINN3_WINDOWS_ENABLED_BLOB "V0lOU19XSU5OM19FTkFCTEVEX1BMQVRGT1JNUz13aW5kb3dz,V0lOU19XSU5OM19EVUFMX0FVVEg9dHJ1ZQ==")
