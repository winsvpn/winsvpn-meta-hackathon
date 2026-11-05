#!/usr/bin/env python3
"""Verify Flutter's wins_vpn/tunnel calls are implemented by Apple bridges.

An Apple bridge is allowed to omit a handler -- iOS and macOS deliberately do
not implement every method Android does. What it is NOT allowed to do is omit a
handler the Dart side can still reach on that platform, because both bridges
end their switch with `default: result(FlutterMethodNotImplemented)`, which the
engine turns into a `MissingPluginException` on the Dart side. An unguarded,
uncaught call to a missing handler is therefore a thrown exception at runtime --
and several of these calls sit on the duress path, where a thrown exception is a
safety failure, not a cosmetic one.

Until 2026-08-06 the exemption list was a bare set of names: writing a method
into it asserted "absence is fine here" and nothing ever checked that claim. So
the list could not distinguish the two cases that matter:

    a missing handler nobody can call            -- correct
    a missing handler the Dart side calls anyway -- a crash on the safety path

Every exemption now has to carry a proof of which one it is, and the proof is
re-checked against lib/main.dart on every run.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DART_SOURCE = ROOT / "lib" / "main.dart"
IOS_BRIDGE = ROOT / "ios" / "Runner" / "AppDelegate.swift"
MACOS_BRIDGE = ROOT / "macos" / "Runner" / "MainFlutterWindow.swift"

APPLE_PLATFORMS = ("ios", "macos")

# The Dart platform predicate that proves a call cannot be reached on a given
# Apple platform.
PLATFORM_GUARD_TOKEN = {
    "ios": "Platform.isIOS",
    "macos": "Platform.isMacOS",
}

# method -> (Apple platforms that MUST implement it, absence proof, why)
#
# The proof is checked, not trusted:
#
#   "caught"          the Dart call sits inside a try block, so the
#                     MissingPluginException is turned into a value and never
#                     propagates. Verified by locating the call in
#                     lib/main.dart and walking its enclosing blocks.
#   "guarded:<token>" the call is controlled by <token>, a Platform predicate
#                     naming a platform that is NOT the exempting one, so the
#                     call is never reached there. Verified the same way: an
#                     enclosing `if`/`else if` condition, an earlier
#                     `if (!<token>) return/throw` at an enclosing level, or
#                     the condition of the conditional expression whose
#                     then-arm holds the call (see guard_controls_call).
PLATFORM_SPECIFIC_METHODS: dict[str, tuple[set[str], str, str]] = {
    # Guarded by `_usesNativeSecureStateStore`, true only on Android, Windows
    # and Linux. Apple keeps VPN configuration and credentials in its existing
    # native Keychain/App Group path instead. These names have no
    # `invokeMethod` call site in lib/main.dart at all, so there is nothing to
    # reach and nothing to prove.
    "deleteSecureText": (set(), "uncalled", "Apple uses the Keychain path."),
    "readSecureText": (set(), "uncalled", "Apple uses the Keychain path."),
    "writeSecureText": (set(), "uncalled", "Apple uses the Keychain path."),
    "setLauncherCamouflage": (
        {"ios"},
        "guarded:Platform.isIOS",
        "Launcher camouflage exists on Android and iOS only.",
    ),
    "resolveCarrierIpv4": (
        set(),
        "guarded:Platform.isAndroid",
        "_resolveXrayCarrierIpv4ForPreflight only invokes this under "
        "`Platform.isAndroid || Platform.isWindows`; Apple takes the dart:io "
        "AF_INET lookup directly, so there is no Apple handler to reach.",
    ),
    "confirmDoubleVpnHandover": (
        set(),
        "guarded:Platform.isAndroid",
        "Double VPN fast-connect handover confirmation (2026-10-24). Fast "
        "connect is Android only: the handover token is minted only on "
        "Android and the call sits under `if (Platform.isAndroid && "
        "handoverToken != null && ...)`, so it cannot be reached on iOS or "
        "macOS and there is no Apple handler to implement.",
    ),
    "setAlwaysOnVpn": (
        set(),
        "guarded:Platform.isAndroid",
        "Always-on VPN is an Android VpnService facility with no Apple "
        "equivalent. `_applyAlwaysOnToNative` returns 'unsupported' before "
        "ever invoking this when not Android, so the call cannot be reached "
        "on iOS or macOS and there is no Apple handler to implement.",
    ),
    # ------------------------------------------------------------------
    # Local account recovery and the tunnel-ingest upload (R11a, 2026-10-16).
    # Apple resets local account data on the Dart side
    # (`_eraseLocalAccountDataKeepingDevice`: purgeAppGroupContainer and
    # purgeAccountDataKeepingCleanupJournal, both implemented natively), so
    # the Android SecureFileStore entry points and the Windows/Linux runtime
    # eraser are never invoked there. Each call is gated in its enclosing
    # Dart function, and the gate is re-proved below on every run.
    "sealAccountStartsForRecovery": (
        set(),
        "guarded:Platform.isAndroid",
        "Seals Android SecureFileStore tunnel starts before the native reset; "
        "the call sits under `if (Platform.isAndroid)`.",
    ),
    "resetAllLocalAccountData": (
        set(),
        "guarded:Platform.isAndroid",
        "Android's native SecureFileStore reset; Apple takes the "
        "`Platform.isAndroid ? ... : _eraseLocalAccountDataKeepingDevice` branch.",
    ),
    "closeAfterAccountRecovery": (
        set(),
        "guarded:Platform.isAndroid",
        "Android finishes the activity after recovery; iOS apps must not "
        "terminate themselves, and the call sits under `if (Platform.isAndroid)`.",
    ),
    "eraseLocalAccountRuntime": (
        set(),
        "guarded:Platform.isWindows",
        "Deletes Windows/Linux runtime configuration copies; reached only under "
        "`if (Platform.isWindows || Platform.isLinux)`. Apple's runtime "
        "configuration lives in the App Group container that "
        "purgeAppGroupContainer erases.",
    ),
    "measureUploadViaTunnelIngest": (
        set(),
        "guarded:Platform.isAndroid",
        "Android raw-socket ingest uploader; `_measureUploadViaTunnelIngest` "
        "returns null before invoking it when not Android, and the third-party "
        "upload families measure Apple.",
    ),
    # ------------------------------------------------------------------
    # Duress SMS. Settled owner decision: iOS duress is a LOCAL WIPE ONLY.
    # There is no relay and no hub, and iOS cannot send an SMS without showing
    # the system compose UI and taking a manual tap, so a covert device-native
    # send is impossible there and is reported honestly rather than faked
    # (`_supportsDeviceNativeSms` returns `Platform.isAndroid`). The Apple
    # bridges are deliberately not party to this contract; implementing these
    # three on Apple would mean implementing a capability the platform does not
    # have.
    #
    # This is the case the old bare-set exemption list could not express, so
    # these three were reported as missing handlers for as long as the section
    # ran. They are exempt AND their absence is proved harmless below: each
    # call is inside a try whose catch returns a safe value (false / both
    # capabilities false), so on Apple the enrollment UI simply never offers an
    # SMS option. `duressSmsCapability` in particular IS called
    # unconditionally, on every platform, from `_promptDuressEnrollment` -- the
    # try is the only thing standing between it and a thrown exception on the
    # duress path, which is exactly why the proof is mechanical from here on.
    "duressSmsCapability": (
        set(),
        "caught",
        "Called unconditionally; catch reports no telephony and no permission.",
    ),
    "requestDuressSmsPermission": (
        set(),
        "caught",
        "SMS enrollment branch only; catch resolves to 'declined'.",
    ),
    "sendDuressSms": (
        set(),
        "caught",
        "Reached only via _supportsDeviceNativeSms; catch resolves to 'not sent'.",
    ),
}


METHOD_CALL_RE = re.compile(
    r"\.invoke(?:Map)?Method(?:<[^>]+>)?\s*\(\s*['\"]([^'\"]+)['\"]",
    re.MULTILINE,
)
SWIFT_CASE_RE = re.compile(r"case\s+\"([^\"]+)\"\s*:")
DART_TYPE_HEADER_RE = re.compile(r"\b(class|extension|mixin|enum)\b[^{;]*$")


def read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8")


# ---------------------------------------------------------------------------
# Dart block analysis.
#
# Enough of a lexer to find which `{ ... }` blocks lexically contain a given
# offset. Strings and comments are skipped so that a brace inside a literal --
# including a `${...}` interpolation, whose own literals may hold an unbalanced
# brace or quote -- cannot shift the nesting. Block comments nest, as in Dart. Getting this wrong would make the proofs below meaningless, so
# `assert_analyzer_is_sound()` positively controls it against known shapes
# before any real answer is used.
# ---------------------------------------------------------------------------
def _block_comment_end(text: str, index: int) -> int:
    """Index just past the block comment opening at `index` (Dart nests them)."""
    depth = 1
    index += 2
    length = len(text)
    while index < length and depth:
        if text.startswith("/*", index):
            depth += 1
            index += 2
        elif text.startswith("*/", index):
            depth -= 1
            index += 2
        else:
            index += 1
    return index


_DART_IDENTIFIER = frozenset(
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_$"
)


def _literal_end(text: str, index: int) -> int:
    """Index just past the Dart string literal whose opening quote is at `index`.

    A raw literal (r'...') has no escapes and no interpolation. Otherwise a
    `${...}` interpolation is Dart code that may hold its own literals, braces
    and comments, so a quote or brace inside it neither ends this literal nor
    shifts the block nesting. An unterminated one-line literal ends at its newline.
    """
    length = len(text)
    raw = (
        index > 0
        and text[index - 1] in "rR"
        and (index < 2 or text[index - 2] not in _DART_IDENTIFIER)
    )
    quote = text[index]
    delimiter = quote * 3 if text.startswith(quote * 3, index) else quote
    position = index + len(delimiter)
    while position < length:
        if text.startswith(delimiter, position):
            return position + len(delimiter)
        if text[position] == "\\" and not raw:
            position += 2
            continue
        if not raw and text.startswith("${", position):
            position = _interpolation_end(text, position + 1)
            continue
        if text[position] == "\n" and len(delimiter) == 1:
            return position
        position += 1
    return length


def _interpolation_end(text: str, brace: int) -> int:
    """Index just past the `}` closing the interpolation whose `{` is at `brace`."""
    length = len(text)
    depth = 1
    position = brace + 1
    while position < length:
        if text.startswith("//", position):
            newline = text.find("\n", position)
            position = length if newline < 0 else newline
            continue
        if text.startswith("/*", position):
            position = _block_comment_end(text, position)
            continue
        char = text[position]
        if char in "'\"":
            position = _literal_end(text, position)
            continue
        if char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return position + 1
        position += 1
    return length


def brace_pairs(text: str) -> list[tuple[int, int]]:
    pairs: list[tuple[int, int]] = []
    stack: list[int] = []
    index = 0
    length = len(text)
    while index < length:
        char = text[index]
        if char == "/" and index + 1 < length:
            following = text[index + 1]
            if following == "/":
                newline = text.find("\n", index)
                index = length if newline < 0 else newline
                continue
            if following == "*":
                index = _block_comment_end(text, index)
                continue
        if char in "'\"":
            index = _literal_end(text, index)
            continue
        if char == "{":
            stack.append(index)
        elif char == "}":
            if stack:
                pairs.append((stack.pop(), index))
        index += 1
    return pairs


def enclosing_blocks(
    text: str, pairs: list[tuple[int, int]], index: int
) -> list[tuple[int, int]]:
    """Blocks containing `index`, innermost first."""
    containing = [pair for pair in pairs if pair[0] < index < pair[1]]
    containing.sort(key=lambda pair: pair[0], reverse=True)
    return containing


def block_header(text: str, open_brace: int) -> str:
    """The source immediately preceding a block's `{`, one statement's worth."""
    start = max(0, open_brace - 400)
    return text[start:open_brace].rstrip()


def enclosing_function_body(
    text: str, pairs: list[tuple[int, int]], index: int
) -> str | None:
    """Body of the innermost enclosing function (not class/extension)."""
    outermost: tuple[int, int] | None = None
    for open_brace, close_brace in enclosing_blocks(text, pairs, index):
        if DART_TYPE_HEADER_RE.search(block_header(text, open_brace)):
            break
        outermost = (open_brace, close_brace)
    if outermost is None:
        return None
    return text[outermost[0] : outermost[1] + 1]


def mask_non_code(text: str) -> str:
    """`text` with comments and string literals blanked to spaces.

    Offsets and newlines are kept, so positions from brace_pairs and the
    METHOD_CALL_RE matches still line up, and a guard token that appears only
    in a comment or a string can never count as code.
    """
    chars = list(text)
    length = len(text)

    def blank(start: int, end: int) -> None:
        for position in range(start, min(end, length)):
            if chars[position] != "\n":
                chars[position] = " "

    index = 0
    while index < length:
        char = text[index]
        if char == "/" and index + 1 < length:
            following = text[index + 1]
            if following == "/":
                newline = text.find("\n", index)
                end = length if newline < 0 else newline
                blank(index, end)
                index = end
                continue
            if following == "*":
                end = _block_comment_end(text, index)
                blank(index, end)
                index = end
                continue
        if char in "'\"":
            end = _literal_end(text, index)
            blank(index, end)
            index = end
            continue
        index += 1
    return "".join(chars)


PLATFORM_PREDICATE_RE = re.compile(r"Platform\.is[A-Za-z]+")


def _statement_tail(masked: str, end: int) -> str:
    """Code from the last statement boundary (`;`, `{`, `}`) up to `end`."""
    start = max(
        masked.rfind(";", 0, end), masked.rfind("{", 0, end), masked.rfind("}", 0, end)
    )
    return masked[start + 1 : end]


def _condition_guards(condition: str, token: str, forbidden: frozenset[str]) -> bool:
    """True when `condition` can only hold where `token` holds.

    Accepted: the token alone, the token as the leading conjunct of an
    `&&` chain with no `||`, or an `||` chain made only of Platform
    predicates that includes the token and names no exempting platform.
    Anything else (a negation, an unknown disjunct) proves nothing.
    """
    condition = " ".join(condition.split())
    if condition == token:
        return True
    if condition.startswith(f"{token} &&") and "||" not in condition:
        return True
    disjuncts = [part.strip() for part in condition.split("||")]
    return (
        token in disjuncts
        and all(PLATFORM_PREDICATE_RE.fullmatch(part) for part in disjuncts)
        and not forbidden.intersection(disjuncts)
    )


def guard_controls_call(
    masked: str,
    pairs: list[tuple[int, int]],
    index: int,
    token: str,
    forbidden: frozenset[str] = frozenset(),
) -> bool:
    """True only when `token` decides whether the call at `index` runs.

    `masked` is mask_non_code() output. A token that merely appears in the
    same function (after the call, in another branch, in a comment) proves
    nothing about reachability, so it is not accepted. Shapes accepted:

      * an enclosing block opened by `if (<condition>)` or
        `else if (<condition>)` where _condition_guards holds;
      * `if (!<token>) return|throw` before the call, at a block level that
        encloses the call, inside the same function;
      * `<token> ? <then-arm holding the call> : ...` in the call's statement.
    """
    containing = enclosing_blocks(masked, pairs, index)
    function_block: tuple[int, int] | None = None
    for open_brace, close_brace in containing:
        if DART_TYPE_HEADER_RE.search(block_header(masked, open_brace)):
            break
        function_block = (open_brace, close_brace)
        head = _statement_tail(masked, open_brace).strip()
        match = re.fullmatch(r"(?:else\s+)?if\s*\((.*)\)", head, re.DOTALL)
        if match and _condition_guards(match.group(1), token, forbidden):
            return True
    if function_block is None:
        return False
    early_exit = re.compile(
        rf"\bif\s*\(\s*!\s*{re.escape(token)}\s*\)\s*(?:\{{\s*)?(?:return|throw)\b"
    )
    enclosing = set(containing)
    for match in early_exit.finditer(masked, function_block[0] + 1, index):
        if all(
            pair in enclosing for pair in enclosing_blocks(masked, pairs, match.start())
        ):
            return True
    tail = _statement_tail(masked, index)
    ternary = None
    for ternary in re.finditer(
        rf"(?:^|(?<![=!<>])=(?!=)|[(,]|=>|\breturn\b)\s*{re.escape(token)}\s*\?(?![?.])",
        tail,
    ):
        pass
    return ternary is not None and ":" not in tail[ternary.end() :]


def is_inside_try(text: str, pairs: list[tuple[int, int]], index: int) -> bool:
    """True when a `try` block encloses `index` and it has a catch/on clause."""
    for open_brace, close_brace in enclosing_blocks(text, pairs, index):
        header = block_header(text, open_brace)
        if DART_TYPE_HEADER_RE.search(header):
            break
        if not header.endswith("try"):
            continue
        trailer = text[close_brace + 1 : close_brace + 40].lstrip()
        if trailer.startswith("catch") or trailer.startswith("on "):
            return True
    return False


def assert_analyzer_is_sound() -> None:
    """Positive control for the analysis above.

    An analyzer that silently answered "yes, it is caught" for everything would
    turn every exemption into a rubber stamp -- the same shape of hole as an
    absence guard that never fires. These shapes pin both answers.
    """
    sample = """
class A {
  Future<void> caught() async {
    try {
      await c.invokeMethod('alpha');
    } catch (_) {}
  }
  Future<void> bare() async {
    await c.invokeMethod('beta');
  }
  Future<void> guarded() async {
    if (!Platform.isIOS) throw StateError('x');
    await c.invokeMethod('gamma');
  }
  Future<void> braceInString() async {
    final s = 'not a block { ';
    await c.invokeMethod('delta');
  }
  Future<void> tokenAfterCall() async {
    await c.invokeMethod('epsilon');
    if (!Platform.isIOS) throw StateError('x');
  }
  Future<void> tokenInCommentAndString() async {
    // if (!Platform.isIOS) return;
    final s = 'if (!Platform.isIOS) return;';
    await c.invokeMethod('zeta');
  }
  Future<bool> ternaryElseArm() async {
    return Platform.isIOS ? false : await c.invokeMethod('eta');
  }
  Future<void> negatedBlock() async {
    if (!Platform.isIOS) {
      await c.invokeMethod('theta');
    }
  }
  Future<void> unknownDisjunct(bool force) async {
    if (Platform.isIOS || force) {
      await c.invokeMethod('iota');
    }
  }
  Future<void> guardedBlock() async {
    if (Platform.isIOS) {
      await c.invokeMethod('kappa');
    }
  }
  Future<bool> ternaryThenArm() async {
    final ok = Platform.isIOS ? await c.invokeMethod('lambda') : false;
    return ok;
  }
  Future<void> elseIfBlock(bool other) async {
    if (other) {
      return;
    } else if (Platform.isIOS) {
      await c.invokeMethod('mu');
    }
  }
  Future<void> guardInPriorFunction() async {
    if (Platform.isIOS) {}
  }
  Future<void> callAfterPriorFunction() async {
    await c.invokeMethod('nu');
  }
  Future<void> earlyExitInSiblingBlock(bool other) async {
    if (other) {
      if (!Platform.isIOS) return;
    }
    await c.invokeMethod('xi');
  }
  Future<void> nestedCommentGuard() async {
    /* outer /* inner */ if (!Platform.isIOS) return; { */
    await c.invokeMethod('omicron');
  }
  Future<void> braceInInterpolatedLiteral(List<String> a) async {
    if (!Platform.isIOS) return;
    final s = '${a.join('{')}';
  }
  Future<void> callAfterInterpolatedBrace() async {
    await c.invokeMethod('pi');
  }
}
"""
    pairs = brace_pairs(sample)
    masked = mask_non_code(sample)
    checks = {
        "alpha": (True, False),
        "beta": (False, False),
        "gamma": (False, True),
        "delta": (False, False),
        "epsilon": (False, False),
        "zeta": (False, False),
        "eta": (False, False),
        "theta": (False, False),
        "iota": (False, False),
        "kappa": (False, True),
        "lambda": (False, True),
        "mu": (False, True),
        "nu": (False, False),
        "xi": (False, False),
        "omicron": (False, False),
        "pi": (False, False),
    }
    for name, (want_try, want_guard) in checks.items():
        at = sample.index(f"'{name}'")
        got_try = is_inside_try(sample, pairs, at)
        got_guard = guard_controls_call(
            masked, pairs, at, "Platform.isIOS", frozenset({"Platform.isMacOS"})
        )
        if got_try != want_try or got_guard != want_guard:
            raise SystemExit(
                "method-channel contract analyzer is unsound: "
                f"{name} try={got_try} (want {want_try}) "
                f"guard={got_guard} (want {want_guard})"
            )


# ---------------------------------------------------------------------------


def dart_channel_methods(text: str) -> set[str]:
    if "MethodChannel('wins_vpn/tunnel')" not in text:
        raise SystemExit("lib/main.dart does not declare the wins_vpn/tunnel MethodChannel.")
    return set(METHOD_CALL_RE.findall(text))


def swift_bridge_methods(path: Path, expected_channel_name: str) -> set[str]:
    text = read_text(path)
    if expected_channel_name not in text:
        raise SystemExit(f"{path.relative_to(ROOT)} does not reference {expected_channel_name}.")
    if "FlutterMethodNotImplemented" not in text:
        raise SystemExit(
            f"{path.relative_to(ROOT)} must end its switch with "
            "`default: result(FlutterMethodNotImplemented)`; without it an "
            "unhandled method's behaviour is undefined and the exemption "
            "proofs below (which assume MissingPluginException) do not hold."
        )
    return set(SWIFT_CASE_RE.findall(text))


def report_methods(label: str, methods: set[str]) -> None:
    print(f"{label}: {', '.join(sorted(methods))}")


def verify_exemption_proofs(dart_text: str) -> list[str]:
    """Re-prove every exemption against the current lib/main.dart.

    Scope, stated plainly: this proves that a missing handler cannot THROW on
    the exempting platform. It does not, and cannot, decide whether the feature
    ought to exist there -- a method that is genuinely required but whose call
    happens to sit in a try would be accepted here. That judgement stays human
    and is recorded in each entry's rationale. What is no longer human is the
    part that was silently wrong: whether the Dart side can reach the call.
    """
    pairs = brace_pairs(dart_text)
    masked = mask_non_code(dart_text)
    problems: list[str] = []
    for method, (required, proof, _why) in sorted(PLATFORM_SPECIFIC_METHODS.items()):
        exempting = [p for p in APPLE_PLATFORMS if p not in required]
        if not exempting:
            continue
        offsets = [
            match.start(1)
            for match in METHOD_CALL_RE.finditer(dart_text)
            if match.group(1) == method
        ]
        if proof == "uncalled":
            if offsets:
                problems.append(
                    f"{method}: exempted as never called, but lib/main.dart "
                    f"invokes it {len(offsets)} time(s)."
                )
            continue
        if not offsets:
            problems.append(
                f"{method}: exemption claims {proof!r}, but lib/main.dart has "
                "no call site -- the exemption is stale and should be removed "
                "or changed to 'uncalled'."
            )
            continue
        for offset in offsets:
            line = dart_text.count("\n", 0, offset) + 1
            if proof == "caught":
                if not is_inside_try(dart_text, pairs, offset):
                    problems.append(
                        f"{method} (lib/main.dart:{line}): exempted from "
                        f"{'/'.join(exempting)} on the claim that the call is "
                        "caught, but it is not inside a try/catch. A missing "
                        "handler here throws MissingPluginException at runtime."
                    )
                continue
            if proof.startswith("guarded:"):
                token = proof.split(":", 1)[1]
                for platform in exempting:
                    if PLATFORM_GUARD_TOKEN.get(platform) == token:
                        problems.append(
                            f"{method}: guard {token!r} cannot justify "
                            f"exempting {platform} -- it is the predicate for "
                            "that very platform."
                        )
                forbidden = frozenset(PLATFORM_GUARD_TOKEN[p] for p in exempting)
                if not guard_controls_call(masked, pairs, offset, token, forbidden):
                    problems.append(
                        f"{method} (lib/main.dart:{line}): exempted from "
                        f"{'/'.join(exempting)} on the claim that it is gated "
                        f"on {token}, but no {token} guard controls the call "
                        "(an enclosing if/else-if condition, an earlier "
                        f"`if (!{token}) return/throw`, or the condition of the "
                        "conditional expression holding it). A mention "
                        "elsewhere in the function proves nothing."
                    )
                continue
            problems.append(f"{method}: unknown absence proof {proof!r}.")
    return problems


def main() -> None:
    assert_analyzer_is_sound()
    dart_text = read_text(DART_SOURCE)
    dart_methods = dart_channel_methods(dart_text)
    ios_methods = swift_bridge_methods(IOS_BRIDGE, "wins_vpn/tunnel")
    macos_methods = swift_bridge_methods(MACOS_BRIDGE, "wins_vpn/tunnel")

    report_methods("Dart tunnel channel calls", dart_methods)
    report_methods("iOS tunnel bridge handlers", ios_methods)
    report_methods("macOS tunnel bridge handlers", macos_methods)

    # An exemption for a method Dart no longer calls, or that a bridge grew a
    # handler for anyway, is dead weight that makes the list less trustworthy.
    stale = sorted(set(PLATFORM_SPECIFIC_METHODS) - dart_methods - {
        "deleteSecureText",
        "readSecureText",
        "writeSecureText",
    })
    if stale:
        print(f"Exemptions with no Dart call site: {', '.join(stale)}")

    def required_on(platform: str) -> set[str]:
        return {
            method
            for method in dart_methods
            if platform
            in PLATFORM_SPECIFIC_METHODS.get(method, ({"ios", "macos"}, "", ""))[0]
        }

    missing_ios = sorted(required_on("ios") - ios_methods)
    missing_macos = sorted(required_on("macos") - macos_methods)
    failed = False
    if missing_ios:
        print(f"Missing iOS handlers: {', '.join(missing_ios)}")
        failed = True
    if missing_macos:
        print(f"Missing macOS handlers: {', '.join(missing_macos)}")
        failed = True

    problems = verify_exemption_proofs(dart_text)
    if problems:
        print("Unproved Apple method-channel exemptions:")
        for problem in problems:
            print(f"  - {problem}")
        failed = True

    if failed:
        raise SystemExit(1)

    exempt_count = sum(
        1
        for _method, (required, _proof, _why) in PLATFORM_SPECIFIC_METHODS.items()
        if set(APPLE_PLATFORMS) - required
    )
    print(
        "Apple method channel contract passed "
        f"({exempt_count} platform exemptions re-proved against lib/main.dart)."
    )


if __name__ == "__main__":
    sys.exit(main())
