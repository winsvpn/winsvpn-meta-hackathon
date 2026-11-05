# Winn v3 descriptor verification ring for Linux flutter_assemble.
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
# Linux release builds advertise the standalone v3 executor compiled into the
# native runner. The encoded platform declaration is kept beside the reviewed
# descriptor ring so direct Flutter/CMake release builds cannot omit it.
# Dual-auth is deliberately absent here. The canonical Linux release producer
# owns the single audited dual-auth argv entry after proving the
# compiled host capability and final AOT runtime. Direct CMake/Flutter builds
# must not be able to advertise that release-only capability.

set(WINN3_RING_DART_DEFINES "V0lOU19XSU5OM19ERVNDUklQVE9SX1BVQktFWV9HMT1MMm1BWWRZSVhQQ0Z1Tm9INW50Z0JCdWJGU25ubHpJQW5Yd0t0dHBlaGFRPQ==,V0lOU19XSU5OM19ERVNDUklQVE9SX1BVQktFWV9HMj1lVkNBSFdYcVVNMSttNW5sVnkySlIrUTQvbWtZR1R4bGsxMTlhaVFoODlNPQ==,V0lOU19XSU5OM19ERVNDUklQVE9SX1BVQktFWV9HMz01M0poc1FCeEtINURHMTQ1TGNhQnVuT1g0bGJ0K0o3SnMwb1B5Sm5qOVEwPQ==,V0lOU19XSU5OM19ERVNDUklQVE9SX1JJTkdfU0hBMjU2PTUyZTkxYzcyY2E1MmQyMzA1OTcyNGUwYTZjMjVjMmY0NWJhZTU3NGE4NWE4NGM4ODRjNWI3ZmQzNjdjYmYwMzI=,V0lOU19XSU5OM19FTkFCTEVEX1BMQVRGT1JNUz1saW51eA==")
