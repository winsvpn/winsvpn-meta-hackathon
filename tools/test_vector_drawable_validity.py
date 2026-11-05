#!/usr/bin/env python3
"""A launcher icon must not ship blank.

WHY THIS EXISTS
---------------
On 2026-08-08 the Wear OS launcher artwork was replaced: a calculator took the
place of a security shield in `ic_launcher_foreground.xml` and
`ic_launcher_monochrome.xml`, and `colors.xml` inverted the adaptive-icon
background from dark navy to light grey so a near-black glyph would still read.
The reason is camouflage, not taste -- `app_name` is permanently "Calculator",
and a shield glyph beside that word is a sharper tell than the honest name was.

Hand-authored `pathData` is the failure mode this class of change carries.
AAPT2 will happily package a `<path>` whose data it cannot parse into anything
visible: the build stays green and the icon renders EMPTY on the device. For an
app whose entire icon strategy is "look unremarkable", a blank tile on the
watch face is the loudest possible outcome -- worse than the shield it replaced,
because an unreadable icon draws exactly the second look the artwork exists to
avoid.

The same applies to a dangling reference. `<adaptive-icon>` naming a
`@drawable` or `@color` that does not exist produces the same blank tile, and
nothing in the Gradle build treats it as an error.

WHAT IT CHECKS
--------------
  1. Every `<vector>` declares a non-zero width/height/viewport.
  2. Every `pathData` parses under the SVG path subset Android accepts:
     known commands, correct parameter counts, numbers that are numbers, arc
     flags that are 0 or 1, and a leading moveto.
  3. Every `fillColor`/`strokeColor` is a literal of legal length or a
     reference that resolves.
  4. Every `<adaptive-icon>` layer resolves to a drawable or colour that exists.

WHY IT IS PYTHON AND NOT A GRADLE TASK. It needs no Android SDK, no Gradle and
no JDK, so `tools/run_test_suite.py` already carries it into CI on every push
and pull request at a 1x multiplier -- and, more to the point, it runs in
milliseconds on the machine where the artwork is being edited, which is where a
malformed path is cheapest to find.

NON-VACUITY IS THE POINT. `test_the_gate_has_teeth` feeds the parser eleven
separately-malformed paths and fails if any is accepted; `test_the_real_icons_parse`
then runs it against the shipped artwork. A validator that accepts everything
would pass the second test while proving nothing, which is the exact failure
mode four other verification artifacts in this project were found to have on
2026-08-08.
"""

from __future__ import annotations

import pathlib
import re
import unittest
import xml.etree.ElementTree as ElementTree
from dataclasses import dataclass

ROOT = pathlib.Path(__file__).resolve().parents[1]
ANDROID_NS = "http://schemas.android.com/apk/res/android"

RES_ROOTS = (
    "android/app/src/main/res",
    "android/devicecheck/app/src/main/res",
    "wear_os/app/src/main/res",
)

# Parameters consumed per repetition of each path command. Android's
# PathParser accepts the SVG 1.1 subset; anything outside this set is dropped
# silently, which is the blank-icon failure this gate exists to catch.
COMMAND_ARITY = {
    "M": 2, "L": 2, "H": 1, "V": 1, "C": 6, "S": 4, "Q": 4, "T": 2, "A": 7, "Z": 0,
}

# Indices, within one arc repetition, of the two flags that must be exactly 0
# or 1. Android's parser reads these positionally; a 2 here silently corrupts
# the rest of the path.
ARC_FLAG_INDICES = (3, 4)

_NUMBER = re.compile(r"[-+]?(?:\d+\.?\d*|\.\d+)(?:[eE][-+]?\d+)?")


class PathDataError(ValueError):
    """A `pathData` string Android cannot render."""


def parse_path_data(data: str) -> int:
    """Validate `data`; return the number of commands parsed.

    Raises `PathDataError` with a specific reason. The count is returned so a
    caller can assert a path is not merely *valid* but non-empty -- a `pathData`
    of `""` parses fine and draws nothing.
    """
    if not data or not data.strip():
        raise PathDataError("empty pathData")

    tokens: list[tuple[str, object]] = []
    i = 0
    n = len(data)
    while i < n:
        ch = data[i]
        if ch in " ,\t\r\n":
            i += 1
            continue
        if ch.isalpha():
            if ch.upper() not in COMMAND_ARITY:
                raise PathDataError(f"unknown path command {ch!r} at offset {i}")
            tokens.append(("cmd", ch))
            i += 1
            continue
        match = _NUMBER.match(data, i)
        if not match:
            raise PathDataError(f"unparseable character {ch!r} at offset {i}")
        tokens.append(("num", float(match.group())))
        i = match.end()

    if not tokens:
        raise PathDataError("pathData contains no commands")
    if tokens[0][0] != "cmd":
        raise PathDataError("pathData must begin with a command, not a number")
    if tokens[0][1] not in ("M", "m"):
        raise PathDataError(
            f"pathData must begin with a moveto (M or m), not {tokens[0][1]!r}"
        )

    commands = 0
    index = 0
    while index < len(tokens):
        kind, value = tokens[index]
        if kind != "cmd":
            raise PathDataError(f"expected a command, found the number {value}")
        command = str(value)
        arity = COMMAND_ARITY[command.upper()]
        index += 1
        commands += 1

        operands: list[float] = []
        while index < len(tokens) and tokens[index][0] == "num":
            operands.append(float(tokens[index][1]))
            index += 1

        if arity == 0:
            if operands:
                raise PathDataError(f"{command!r} takes no parameters, got {len(operands)}")
            continue
        if not operands:
            raise PathDataError(f"{command!r} needs {arity} parameter(s), got none")
        if len(operands) % arity:
            raise PathDataError(
                f"{command!r} needs a multiple of {arity} parameter(s), got {len(operands)}"
            )
        if command.upper() == "A":
            for repetition in range(len(operands) // arity):
                base = repetition * arity
                for flag_index in ARC_FLAG_INDICES:
                    flag = operands[base + flag_index]
                    if flag not in (0.0, 1.0):
                        raise PathDataError(
                            f"arc flag must be 0 or 1, got {flag} in parameter "
                            f"{flag_index + 1} of an {command!r} command"
                        )
    return commands


_HEX_COLOR = re.compile(r"^#(?:[0-9a-fA-F]{3,4}|[0-9a-fA-F]{6}|[0-9a-fA-F]{8})$")


@dataclass(frozen=True)
class Problem:
    path: str
    detail: str

    def __str__(self) -> str:
        return f"{self.path}: {self.detail}"


def _android(element: ElementTree.Element, name: str) -> str | None:
    return element.get(f"{{{ANDROID_NS}}}{name}")


def is_source(path: pathlib.Path) -> bool:
    """False for files that are not resources anybody authored.

    `.bak_*` are this project's edit snapshots. `._*` are macOS AppleDouble
    resource forks -- this tree is full of them (they are created whenever it is
    copied to a non-APFS volume) and they are binary, so an XML parser reports
    every one as malformed. Treating them as artwork would make this gate red on
    fourteen files that do not exist as far as the Android build is concerned,
    which is how a gate gets switched off.
    """
    name = path.name
    return not name.startswith("._") and ".bak_" not in name


def _declared_resources(res_root: pathlib.Path) -> dict[str, set[str]]:
    """Resource names declared under `res_root`, keyed by type."""
    declared: dict[str, set[str]] = {"drawable": set(), "color": set(), "mipmap": set()}
    for child in sorted(res_root.glob("*")):
        if not child.is_dir():
            continue
        kind = child.name.split("-", 1)[0]
        if kind in ("drawable", "mipmap"):
            for item in child.iterdir():
                if not is_source(item):
                    continue
                declared[kind].add(item.name.split(".", 1)[0])
        elif kind == "values":
            for item in child.glob("*.xml"):
                if not is_source(item):
                    continue
                try:
                    tree = ElementTree.parse(item)
                except ElementTree.ParseError:
                    continue
                for node in tree.getroot():
                    if node.tag == "color" and node.get("name"):
                        declared["color"].add(str(node.get("name")))
    return declared


def _check_reference(value: str, declared: dict[str, set[str]], where: str) -> str | None:
    """None when `value` is a legal literal or a reference that resolves."""
    value = value.strip()
    if not value:
        return f"{where} is empty"
    if value.startswith("#"):
        if not _HEX_COLOR.match(value):
            return f"{where} {value!r} is not a legal #RGB/#ARGB/#RRGGBB/#AARRGGBB literal"
        return None
    if value.startswith("?"):
        # A theme attribute. Resolved at runtime against the applied theme;
        # not checkable from the resource tree alone.
        return None
    match = re.match(r"^@(?:android:)?(\w+)/(\w+)$", value)
    if not match:
        return f"{where} {value!r} is neither a colour literal nor a resource reference"
    kind, name = match.group(1), match.group(2)
    if value.startswith("@android:"):
        return None
    if kind not in declared:
        return None
    if name not in declared[kind]:
        return f"{where} references @{kind}/{name}, which is not declared in this module"
    return None


def check_resource_root(res_root: pathlib.Path) -> list[Problem]:
    problems: list[Problem] = []
    declared = _declared_resources(res_root)

    for xml_path in sorted(res_root.rglob("*.xml")):
        if not is_source(xml_path):
            continue
        rel = (
            xml_path.relative_to(ROOT).as_posix()
            if xml_path.is_relative_to(ROOT)
            else xml_path.as_posix()
        )
        try:
            root_element = ElementTree.parse(xml_path).getroot()
        except ElementTree.ParseError as exc:
            problems.append(Problem(rel, f"is not well-formed XML: {exc}"))
            continue

        if root_element.tag == "adaptive-icon":
            for layer in ("background", "foreground", "monochrome"):
                node = root_element.find(layer)
                if node is None:
                    if layer != "monochrome":
                        problems.append(Problem(rel, f"<adaptive-icon> has no <{layer}>"))
                    continue
                reference = _android(node, "drawable")
                if reference is None:
                    problems.append(
                        Problem(rel, f"<{layer}> has no android:drawable")
                    )
                    continue
                issue = _check_reference(reference, declared, f"<{layer}> android:drawable")
                if issue:
                    problems.append(Problem(rel, issue))
            continue

        if root_element.tag != "vector":
            continue

        for attribute in ("width", "height", "viewportWidth", "viewportHeight"):
            raw = _android(root_element, attribute)
            if raw is None:
                problems.append(Problem(rel, f"<vector> is missing android:{attribute}"))
                continue
            numeric = _NUMBER.match(raw.strip())
            if not numeric or float(numeric.group()) <= 0:
                problems.append(
                    Problem(rel, f"<vector> android:{attribute}={raw!r} must be a positive number")
                )

        paths = list(root_element.iter("path"))
        if not paths:
            problems.append(Problem(rel, "<vector> contains no <path>; it would render blank"))

        for index, path_element in enumerate(paths, start=1):
            label = f"<path> #{index}"
            data = _android(path_element, "pathData")
            if data is None:
                problems.append(Problem(rel, f"{label} has no android:pathData"))
                continue
            try:
                commands = parse_path_data(data)
            except PathDataError as exc:
                problems.append(Problem(rel, f"{label} android:pathData is invalid -- {exc}"))
                continue
            if commands == 0:
                problems.append(Problem(rel, f"{label} android:pathData draws nothing"))

            fill = _android(path_element, "fillColor")
            stroke = _android(path_element, "strokeColor")
            if fill is None and stroke is None:
                problems.append(
                    Problem(rel, f"{label} has neither fillColor nor strokeColor; it is invisible")
                )
            for attribute, value in (("fillColor", fill), ("strokeColor", stroke)):
                if value is None:
                    continue
                issue = _check_reference(value, declared, f"{label} android:{attribute}")
                if issue:
                    problems.append(Problem(rel, issue))

    return problems


def scan_repository() -> list[Problem]:
    problems: list[Problem] = []
    for root in RES_ROOTS:
        res_root = ROOT / root
        if res_root.is_dir():
            problems.extend(check_resource_root(res_root))
    return problems


class VectorDrawableValidity(unittest.TestCase):
    """Hand-authored icon artwork must render."""

    # ---- non-vacuity: the parser must reject malformed paths -------------

    def test_the_gate_has_teeth(self) -> None:
        """Every one of these must be rejected, with a reason."""
        malformed = {
            "": "empty",
            "   ": "whitespace only",
            "38,26h32": "no leading command",
            "M38,26h32Z@": "illegal character",
            "M38,26 X10,10": "unknown command X",
            "M38": "moveto with one parameter",
            "M38,26h": "trailing command with no parameters",
            "M38,26 L10": "lineto with an odd parameter count",
            "M38,26 C1,2,3,4,5": "curveto with five parameters",
            "M38,26 a6,6 0 3 1 6,6": "arc large-arc flag of 3",
            "M38,26 a6,6 0 0 7 6,6": "arc sweep flag of 7",
            "M38,26 Z 5": "closepath with a parameter",
            "L10,10 M0,0": "starts with a lineto",
        }
        for data, why in malformed.items():
            with self.subTest(why=why):
                with self.assertRaises(PathDataError, msg=f"accepted {why}: {data!r}"):
                    parse_path_data(data)

    def test_the_gate_accepts_the_real_artwork_grammar(self) -> None:
        """The forms the shipped icons actually use must parse."""
        # The wear calculator body: implicit-repeat h/v plus rounded corners.
        self.assertGreater(
            parse_path_data("M38,26h32a6,6 0 0 1 6,6v44a6,6 0 0 1 -6,6h-32a6,6 0 0 1 -6,-6v-44a6,6 0 0 1 6,-6z"),
            0,
        )
        # The key grid: six subpaths under one command run.
        self.assertGreater(
            parse_path_data("M38,54h8v10h-8zM50,54h8v10h-8zM62,54h8v10h-8z"), 0
        )
        # Exponent and leading-dot number forms are legal SVG.
        self.assertGreater(parse_path_data("M1e2,.5 L.5,1e-2 Z"), 0)
        # Implicit repetition of an implicit lineto after a moveto.
        self.assertGreater(parse_path_data("M0,0 10,10 20,20"), 0)

    def test_a_dangling_adaptive_icon_layer_is_caught(self) -> None:
        """The other way an icon ships blank."""
        import tempfile

        with tempfile.TemporaryDirectory() as temporary:
            res = pathlib.Path(temporary) / "res"
            (res / "mipmap-anydpi-v26").mkdir(parents=True)
            (res / "drawable").mkdir(parents=True)
            (res / "mipmap-anydpi-v26" / "ic_launcher.xml").write_text(
                '<?xml version="1.0" encoding="utf-8"?>\n'
                '<adaptive-icon xmlns:android="http://schemas.android.com/apk/res/android">\n'
                '  <background android:drawable="@color/does_not_exist" />\n'
                '  <foreground android:drawable="@drawable/also_missing" />\n'
                "</adaptive-icon>\n",
                encoding="utf-8",
            )
            problems = check_resource_root(res)
            self.assertEqual(
                2,
                len(problems),
                "both dangling layers must be reported: "
                + "; ".join(str(p) for p in problems),
            )

    # ---- the real artwork -------------------------------------------------

    def test_the_scan_actually_reaches_the_icons(self) -> None:
        """Guards against a green that only means 'found no files'."""
        vectors = 0
        for root in RES_ROOTS:
            res_root = ROOT / root
            if not res_root.is_dir():
                continue
            for xml_path in res_root.rglob("*.xml"):
                if not is_source(xml_path):
                    continue
                try:
                    if ElementTree.parse(xml_path).getroot().tag in ("vector", "adaptive-icon"):
                        vectors += 1
                except ElementTree.ParseError:
                    vectors += 1
        self.assertGreaterEqual(
            vectors, 8, "expected the shipped vector artwork to be found; got %d" % vectors
        )

    def test_the_wear_launcher_artwork_changed_today_is_valid(self) -> None:
        """The 2026-08-08 calculator icon specifically."""
        wear = ROOT / "wear_os/app/src/main/res"
        self.assertTrue(wear.is_dir(), "wear_os resource root is missing")
        problems = check_resource_root(wear)
        self.assertEqual([], problems, "\n" + "\n".join(str(p) for p in problems))

    def test_every_vector_drawable_is_valid(self) -> None:
        problems = scan_repository()
        self.assertEqual([], problems, "\n\n" + "\n".join(str(p) for p in problems) + "\n")


if __name__ == "__main__":
    unittest.main(verbosity=2)
