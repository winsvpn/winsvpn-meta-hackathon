#!/usr/bin/env python3
"""Build the Burmese variant of the donor tax letter and render it to WebP.

    # layout proof with generated Burmese filler (safe, never publishable)
    python3 build_my_svg.py --placeholder

    # the real thing, once a human translation is in donor-letter.my.csv
    python3 build_my_svg.py --translation donor-letter.my.csv --final

Why this exists
---------------
SVG <text> does not wrap, so the English letter is 92 hand-placed lines. Burmese
cannot be wrapped that way: it is written without spaces between words, so
splitting on " " produces either one enormous line or breaks in the middle of a
word. Chrome carries ICU, which knows where Burmese words end. So this script
lays every block out in a headless Chrome page at the exact font, size and
column width the SVG will use, reads the real line boxes back out, and emits one
<text> element per line at the position Chrome chose.

The page must stay US Letter portrait (816x1056 user units) because the
published asset is 1200x1553. Burmese needs more leading than Latin, and the
Burmese edition carries two blocks the English one does not, so the flow engine
auto-fits: it shrinks a single global body scale until the content fits, and
refuses to emit anything if it cannot fit above the floor.

No model is loaded and nothing is deployed. Chrome is used headless, twice per
fit iteration, for measurement and once for the screenshot.
"""
from __future__ import annotations

import argparse
import base64
import csv
import html as H
import json
import pathlib
import random
import re
import shutil
import subprocess
import sys
import tempfile

HERE = pathlib.Path(__file__).resolve().parent
REPO = HERE.parents[3]
EN_SVG = REPO / "brand" / "donor_recognition" / "donor-tax-deduction-letter.svg"
PKG = HERE / "donor-letter.segments.json"
PROOF = HERE / "proof"
ASSETS = REPO / "web" / "assets"

CHROME = "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"
FONT = ("Aptos,'Segoe UI Variable','Segoe UI','Helvetica Neue',Helvetica,"
        "Arial,'Noto Sans Myanmar','Myanmar MN',sans-serif")

PAGE_W, PAGE_H = 816, 1056
OUT_W, OUT_H = 1200, 1553
THUMB_W, THUMB_H = 420, 544

MERGED = "MERGED"

# English gloss printed under the Burmese scope notice. Deliberately shorter
# than the notice.scope source in donor-letter.segments.json: the page has one
# line to spend here, and the full English lives in the segment package and in
# TRANSLATOR-BRIEF.md. Keep the two saying the same thing.
SCOPE_EN_GLOSS = ("United States federal tax rules. They change what you owe "
                  "only if you file a United States federal return, which most "
                  "readers in Myanmar do not. The English edition of this "
                  "letter does not say so.")
CONTENT_X, CONTENT_R = 56.0, 760.0          # body column
BOX_PAD = 20.0                              # callout inner padding
# Last usable baseline. The paper panel ends at y=1020. The English edition
# puts its footer baseline at 1005.6 and keeps 14 units of white below it; this
# edition carries two notices the English one does not, so it spends some of
# that margin and keeps 6, which still clears the descender of an 8.5 unit
# line by about 4 units. Anything past this is clipping, and the builder
# refuses rather than clip.
BOTTOM_LIMIT = 1014.0

# Burmese needs more leading than Latin: stacked medials and below-vowels sit
# outside the Latin em box. These numbers are measured, not guessed. Canvas
# TextMetrics on this machine, at the font stack below, gives the ink extents
# of a Burmese line as:
#
#   typical prose                       1.47 em   (ascent 1.003 + descent 0.467)
#   tall stacks (ဤ ဿ ဋ္ဌ ဏ္ဍ)             1.48 em
#   deep below-marks (ကျွန်ုပ် ဆူ ဗူ)      1.54 em
#   worst mixed line                    1.56 em
#   Latin, for comparison               1.01 em
#
# So 1.56 is the leading at which two adjacent lines can never touch, and 1.47
# is the leading at which ordinary prose never touches. The fit engine is
# allowed to compress between those two and no further: below 1.47 even normal
# Burmese collides, which is a defect, not a tight layout.
MM_LEADING = 1.52
MM_LEADING_FLOOR = 1.47
LAT_LEADING = 1.32

PALETTE = {
    "ink": "#102033", "body": "#53627a", "mute": "#6b7f96",
    "blue": "#0a65d8", "pale": "#cfe9ff", "white": "#ffffff",
    "cyan": "#7fd8f5", "pill": "#d8f1ff", "foot": "#8aa0b8",
}


# ==========================================================================
# Burmese filler for the layout proof.
#
# Every entry is a complete, well formed Burmese cluster, so concatenating them
# never produces a broken cluster or a dotted circle. Concatenated they are
# nonsense, the way lorem ipsum is nonsense: representative of the script's
# width and height, impossible to mistake for a translation.
# ==========================================================================
SYLL = [
    "ကျွန်", "ုပ်", "တို့", "သည်", "မြန်", "မာ", "နိုင်", "ငံ", "အခွန်", "ဆောင်",
    "ရွက်", "ချက်", "များ", "ဖြစ်", "ပါ", "သော", "ကြောင့်", "အတွက်", "နှင့်",
    "မှာ", "တွင်", "ကို", "သို့", "လှူ", "ဒါန်း", "မှု", "လျှော့", "ချ", "ငွေ",
    "ကြေး", "ပြည်", "ထောင်", "စု", "အစိုး", "ရ", "စာ", "ရေး", "သား", "ထား",
    "သည့်", "အချက်", "အလက်", "ကောင်း", "မွန်", "စွာ", "လုပ်", "ငန်း", "ဆောင်",
    "တာ", "ရှိ", "သ", "မျှ", "ပေး", "ဆပ်", "နှုန်း", "ထား", "တန်", "ဖိုး",
    "ရည်", "ညွှန်း", "ဥပ", "ဒေ", "အရ", "သတ်", "မှတ်", "ဖော်", "ပြ", "နေ",
]


def filler(n_clusters: int, rng: random.Random) -> str:
    if n_clusters <= 0:
        return ""
    return "".join(rng.choice(SYLL) for _ in range(n_clusters))


FIGURE_RE = re.compile(r"\$?\d{1,3}(?:,\d{3})+(?:\.\d+)?%?|\$?\d+(?:\.\d+)?%?")


def placeholder_for(src: str, en_width: float, rng: random.Random,
                    ratio: float, per_cluster: float, fig_width: float) -> str:
    """Filler of the same *measured* rendered width as `src`.

    `en_width` is the real width Chrome gave the English source at the
    calibration size, not an estimate from character count: English character
    widths vary too much for a per-character average to be honest here.

    Figures stay exactly as printed, in Western Arabic digits, in source order,
    so the digit checker and the layout both get a real workout.
    """
    figs = FIGURE_RE.findall(src)
    target = en_width * ratio - fig_width
    clusters = max(1, int(round(max(0.0, target) / per_cluster)))
    if not figs:
        return filler(clusters, rng)
    share = max(1, clusters // (len(figs) + 1))
    out = [filler(share, rng)]
    for f in figs:
        out.append(" %s " % f)
        out.append(filler(share, rng))
    return "".join(out).strip()


# ==========================================================================
# Chrome bridge
# ==========================================================================
def chrome_eval(page_html: str, tmp: pathlib.Path, tag: str) -> list:
    """Render `page_html` headless and read the JSON its script leaves behind."""
    p = tmp / ("%s.html" % tag)
    p.write_text(page_html, encoding="utf-8")
    r = subprocess.run(
        [CHROME, "--headless", "--disable-gpu", "--no-sandbox",
         "--no-first-run", "--disable-extensions", "--force-device-scale-factor=1",
         "--virtual-time-budget=15000", "--dump-dom", "file://%s" % p],
        capture_output=True, text=True, timeout=180)
    m = re.search(r'<pre id="payload">(.*?)</pre>', r.stdout, re.S)
    if not m:
        sys.stderr.write(r.stderr[-3000:] + "\n")
        raise SystemExit("chrome measurement produced no payload (%s)" % tag)
    return json.loads(H.unescape(m.group(1)))


MEASURE_JS = r"""
<script>
function lineSplit(el){
  var out=[], node=null;
  for (var c=el.firstChild; c; c=c.nextSibling){ if(c.nodeType===3){node=c;break;} }
  if(!node) return [el.textContent];
  var s=node.textContent, rng=document.createRange();
  var start=0, curTop=null, lh=parseFloat(getComputedStyle(el).lineHeight)||12;
  for(var i=0;i<s.length;i++){
    rng.setStart(node,i); rng.setEnd(node,i+1);
    var rects=rng.getClientRects();
    if(!rects.length) continue;
    var t=rects[0].top;
    if(curTop===null){ curTop=t; }
    else if(t > curTop + lh*0.45){ out.push(s.slice(start,i)); start=i; curTop=t; }
  }
  out.push(s.slice(start));
  return out.map(function(x){ return x.replace(/^[\s​]+|[\s​]+$/g,''); })
            .filter(function(x){ return x.length>0; });
}
window.addEventListener('load', function(){
  var out=[];
  document.querySelectorAll('[data-key]').forEach(function(el){
    var lines = el.dataset.mode==='width' ? null : lineSplit(el);
    var r = el.getBoundingClientRect();
    var rec = {key: el.dataset.key, w: +r.width.toFixed(3), h: +r.height.toFixed(3)};
    if(lines){
      rec.lines = lines;
      rec.widths = lines.map(function(t){
        var probe=document.createElement('span');
        probe.style.cssText=getComputedStyle(el).cssText;
        probe.style.position='absolute'; probe.style.whiteSpace='pre';
        probe.style.width='auto'; probe.style.visibility='hidden';
        probe.textContent=t; document.body.appendChild(probe);
        var w=probe.getBoundingClientRect().width; probe.remove();
        return +w.toFixed(3);
      });
    }
    out.push(rec);
  });
  var pre=document.createElement('pre'); pre.id='payload';
  pre.textContent=JSON.stringify(out); document.body.appendChild(pre);
});
</script>
"""


def measure(items: list[dict], tmp: pathlib.Path, tag: str) -> dict:
    """items: [{key, text, size, weight, width|None, spacing}] -> {key: record}"""
    parts = ['<!doctype html><meta charset="utf-8">',
             '<body style="margin:0;padding:0">']
    for it in items:
        style = ("font-family:%s;font-size:%.4fpx;font-weight:%s;"
                 "line-height:%.4fpx;margin:0;padding:0;"
                 "font-variant-ligatures:none;"
                 % (FONT, it["size"], it.get("weight", "normal"),
                    it.get("leading", it["size"] * 1.6)))
        if it.get("spacing"):
            style += "letter-spacing:%.3fpx;" % it["spacing"]
        if it.get("width"):
            style += ("width:%.4fpx;white-space:normal;word-break:normal;"
                      "line-break:auto;overflow-wrap:normal;" % it["width"])
            mode = "wrap"
        else:
            style += "display:inline-block;white-space:pre;"
            mode = "width"
        parts.append('<div data-key="%s" data-mode="%s" style="%s">%s</div>'
                     % (H.escape(it["key"], True), mode, style,
                        H.escape(it["text"])))
    parts.append(MEASURE_JS)
    parts.append("</body>")
    recs = chrome_eval("".join(parts), tmp, tag)
    return {r["key"]: r for r in recs}


# ==========================================================================
# Layout
# ==========================================================================
def esc(s: str) -> str:
    return (s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;"))


class Doc:
    def __init__(self) -> None:
        self.body: list[str] = []
        self.last_y: float = 0.0

    def add(self, s: str) -> None:
        self.body.append(s)

    def text(self, x: float, y: float, s: str, size: float, weight,
             fill: str, anchor: str = "start", spacing: float | None = None,
             opacity: float | None = None) -> None:
        a = ['x="%.3f"' % x, 'y="%.3f"' % y, 'font-size="%.3f"' % size]
        if weight:
            a.append('font-weight="%s"' % weight)
        a.append('fill="%s"' % fill)
        if anchor != "start":
            a.append('text-anchor="%s"' % anchor)
        if spacing:
            a.append('letter-spacing="%.3f"' % spacing)
        if opacity is not None:
            a.append('opacity="%.2f"' % opacity)
        self.add("<text %s>%s</text>" % (" ".join(a), esc(s)))
        self.last_y = max(self.last_y, y)


def read_targets(path: pathlib.Path) -> dict[str, str]:
    if path.suffix.lower() == ".json":
        raw = json.loads(path.read_text(encoding="utf-8"))
        if isinstance(raw, dict) and "segment_list" in raw:
            return {s["id"]: (s.get("target_my") or "")
                    for s in raw["segment_list"]}
        return {str(k): (v or "") for k, v in raw.items()}
    out: dict[str, str] = {}
    with path.open(encoding="utf-8-sig", newline="") as fh:
        for row in csv.DictReader(fh):
            sid = (row.get("id") or "").strip()
            if sid:
                out[sid] = (row.get("burmese_translation") or "").strip()
    return out


def block_texts(pkg: dict, targets: dict[str, str]) -> dict[str, str]:
    acc: dict[str, list[str]] = {}
    for s in pkg["segment_list"]:
        t = targets.get(s["id"], "").strip()
        if t.upper() == MERGED:
            continue
        acc.setdefault(s["block"], []).append(t)
    return {b: " ".join(x for x in v if x).strip() for b, v in acc.items()}


def en_block_texts(pkg: dict) -> dict[str, str]:
    acc: dict[str, list[str]] = {}
    for s in pkg["segment_list"]:
        acc.setdefault(s["block"], []).append(s["source_en"])
    return {b: " ".join(v).strip() for b, v in acc.items()}


# Blocks that must stay in Latin no matter what the translator does.
VERBATIM = {"hdr.org", "sign.org", "footer.domain"}


def build(scale: float, texts: dict[str, str], en: dict[str, str],
          tmp: pathlib.Path, tag: str, placeholder: bool):
    """One layout attempt. Returns (svg_string, bottom_y, stats) or raises."""
    S = scale
    ML = max(MM_LEADING_FLOOR, MM_LEADING - (1.0 - S) * 0.35)

    # ---- font sizes -----------------------------------------------------
    # Burmese runs taller than Latin and this edition carries two blocks the
    # English one does not, so the page has to give something up. It gives it
    # up where it costs the reader least. Each size carries a compressibility
    # weight: 0 would hold the size fixed, 1 takes the full fit scale, above 1
    # absorbs more than its share. The caveat box, the scope notice and the
    # title are held near full size on purpose; the fine print, the table and
    # the footnote take the strain.
    BASE = {
        "kicker": 8.5, "title": 19.0, "sub": 10.4, "salut": 11.5,
        "intro": 10.0, "callout_h": 8.5, "callout": 9.4, "sec": 8.5,
        "body": 10.0, "tbl_h": 7.0, "tbl_gift": 11.0, "tbl_cell": 8.3,
        "tbl_val": 9.5, "tbl_note": 7.4, "foot": 8.2, "ceil": 9.6,
        "sign_org": 12.5, "sign_suf": 8.6, "fine": 7.2, "domain": 8.5,
        "notice": 9.2, "notice_en": 6.4, "gov": 7.6, "gov_en": 6.6,
    }
    WEIGHT = {
        # held closest to full size: the caveat and the scope notice are the
        # two things a reader must not have to squint at
        "callout": 0.30, "callout_h": 0.30, "notice": 0.30,
        "title": 0.55, "salut": 0.70, "sub": 0.75, "kicker": 0.85,
        # ordinary prose
        "intro": 0.90, "body": 0.90, "ceil": 0.90, "sec": 0.90,
        "sign_org": 1.00, "sign_suf": 1.00, "domain": 1.00,
        "notice_en": 1.10, "gov": 1.00, "gov_en": 1.20,
        # supporting matter absorbs the compression
        "tbl_h": 1.35, "tbl_gift": 1.20, "tbl_cell": 1.35, "tbl_val": 1.25,
        "tbl_note": 1.40, "foot": 1.45, "fine": 1.50,
    }
    # No size is ever compressed below SIZE_FLOOR of its base, whatever the
    # weight says. The English edition already sets its fine print at 7.2
    # units (about 5.4pt at print size); letting the Burmese one fall below
    # that would trade a legal notice for a layout convenience.
    SIZE_FLOOR = 0.86
    fs = {k: v * max(SIZE_FLOOR, 1.0 - (1.0 - S) * WEIGHT.get(k, 1.0))
          for k, v in BASE.items()}

    body_w = CONTENT_R - CONTENT_X                       # 704
    box_x = CONTENT_X
    box_w = body_w
    box_text_x = box_x + BOX_PAD
    box_text_w = box_w - 2 * BOX_PAD

    # ---- measurement request -----------------------------------------
    def M(key, text, size, weight=None, width=None, spacing=None):
        return {"key": key, "text": text, "size": size,
                "weight": weight or "normal", "width": width,
                "spacing": spacing,
                "leading": size * (LAT_LEADING if key in VERBATIM
                                   else ML)}

    req = [
        # the letterhead band is a fixed 96 units tall, so it never scales
        M("hdr.org", texts["hdr.org"], 15, 800, spacing=1.5),
        M("hdr.status", texts["hdr.status"], 7.4, 700, width=330),
        M("hdr.exempt", texts["hdr.exempt"], 7.4, 700, width=330),
        M("hdr.taxyear", texts["hdr.taxyear"], 11, 780),
        M("ttl.kicker", texts["ttl.kicker"], fs["kicker"], 780, width=body_w),
        M("ttl.title", texts["ttl.title"], fs["title"], 780, width=body_w),
        M("ttl.sub", texts["ttl.sub"], fs["sub"], 520, width=body_w - 60),
        M("body.salutation", texts["body.salutation"], fs["salut"], 700),
        M("intro", texts["body.p1"] + " " + texts["body.p2"], fs["intro"],
          None, width=body_w),
        M("notice.scope", texts["notice.scope"], fs["notice"], 600,
          width=box_text_w),
        M("notice.scope.en", SCOPE_EN_GLOSS, fs["notice_en"], 500,
          width=box_text_w),
        M("callout.head", texts["callout.head"], fs["callout_h"], 800,
          width=box_text_w),
        M("callout.body", texts["callout.body"], fs["callout"], 500,
          width=box_text_w),
        M("arith.head", texts["arith.head"], fs["sec"], 800, width=body_w),
        M("arith.body", texts["arith.body"], fs["body"], None, width=body_w),
        M("tbl.head", texts["tbl.head"], fs["sec"], 800, width=body_w),
        M("tbl.footnote", texts["tbl.footnote"], fs["foot"], 500, width=body_w),
        M("ceil.head", texts["ceil.head"], fs["sec"], 800, width=body_w),
        M("ceil.lead", texts["ceil.lead"], fs["ceil"], 800),
        M("ack.lead", texts["ack.lead"], fs["ceil"], 800),
        M("ceilbody", texts["ceil.body"], fs["ceil"], None, width=body_w),
        M("ackbody", texts["ack.body"], fs["ceil"], None, width=body_w),
        M("cannot.head", texts["cannot.head"], fs["sec"], 800, width=body_w),
        M("cannot.body", texts["cannot.body"], fs["ceil"], None, width=body_w),
        M("sign.closing", texts["sign.closing"], fs["body"], None),
        M("sign.org", texts["sign.org"], fs["sign_org"], 800),
        M("sign.orgsuffix", texts["sign.orgsuffix"], fs["sign_suf"], 550),
        M("notice.governing", texts["notice.governing"], fs["gov"], 700,
          width=body_w),
        M("notice.governing.en", en["notice.governing"], fs["gov_en"], 500,
          width=body_w),
        M("fine.print", texts["fine.print"], fs["fine"], 500, width=body_w),
        M("footer.domain", texts["footer.domain"], fs["domain"], 750),
    ]
    # table cells
    COLS = {"gift": (63.0, 68.0), "assume": (131.0, 205.0),
            "deduct": (341.0, 148.0), "rate": (491.0, 80.0),
            "reduction": (573.0, 98.0), "netcost": (673.0, 85.0)}
    # column key -> block id suffix
    HEADKEY = {"gift": "gift", "assume": "assumptions", "deduct": "deduct",
               "rate": "rate", "reduction": "reduction", "netcost": "netcost"}
    for name, (cx, cw) in COLS.items():
        req.append(M("tbl.col." + name, texts["tbl.col." + HEADKEY[name]],
                     fs["tbl_h"], 800, width=cw))
    for i in (1, 2, 3, 4):
        req.append(M("row%d.gift" % i, texts["row%d.gift" % i],
                     fs["tbl_gift"], 800))
        req.append(M("row%d.assume" % i, texts["row%d.assume" % i],
                     fs["tbl_cell"], 500, width=COLS["assume"][1]))
        req.append(M("row%d.deduct" % i, texts["row%d.deduct" % i],
                     fs["tbl_val"], 800))
        req.append(M("row%d.note" % i, texts["row%d.note" % i],
                     fs["tbl_note"], 500, width=COLS["deduct"][1]))
        req.append(M("row%d.rate" % i, texts["row%d.rate" % i],
                     fs["tbl_val"], 700))
        req.append(M("row%d.reduction" % i, texts["row%d.reduction" % i],
                     fs["tbl_val"], 800, width=COLS["reduction"][1]))
        req.append(M("row%d.netcost" % i, texts["row%d.netcost" % i],
                     fs["tbl_val"], 700, width=COLS["netcost"][1]))

    m = measure(req, tmp, tag)

    def lines(key: str) -> list[str]:
        return m[key].get("lines") or [m[key].get("text", "")] or [""]

    def nlines(key: str) -> int:
        return max(1, len(m[key].get("lines", [""])))

    # ---- emit ---------------------------------------------------------
    d = Doc()
    logo = re.search(r'href="(data:image/webp;base64,[^"]+)"',
                     EN_SVG.read_text(encoding="utf-8")).group(1)

    d.add('<rect width="816" height="1056" fill="#ffffff"/>')
    d.add('<rect x="36" y="36" width="744" height="984" fill="url(#dl-paper)"/>')
    d.add('<rect x="28" y="28" width="760" height="1000" fill="none" '
          'stroke="#102033" stroke-width="2.2"/>')
    d.add('<rect x="36" y="36" width="744" height="984" fill="none" '
          'stroke="#9ec9ef" stroke-width="0.9"/>')
    d.add('<rect x="37" y="37" width="742" height="96" fill="url(#dl-head)"/>')
    d.add('<rect x="50" y="43" width="154.23" height="84" rx="6" '
          'fill="#050f1a"/>')
    d.add('<image x="50" y="43" width="154.23" height="84" '
          'preserveAspectRatio="xMidYMid meet" clip-path="url(#dl-logoclip)" '
          'href="%s"><title>Win’s VPN Inc. logo</title></image>' % logo)
    d.add('<rect x="50" y="43" width="154.23" height="84" rx="6" fill="none" '
          'stroke="#4f9ad0" stroke-width="1" opacity="0.55"/>')
    d.add('<rect x="222" y="53" width="0.9" height="64" fill="#3d7ba8" '
          'opacity="0.7"/>')

    d.text(240, 79, texts["hdr.org"], 15, 800, PALETTE["white"], spacing=1.5)
    y = 97
    for ln in lines("hdr.status"):
        d.text(240, y, ln, 7.4, 700, PALETTE["cyan"])
        y += 11
    for ln in lines("hdr.exempt"):
        d.text(240, y, ln, 7.4, 700, PALETTE["cyan"])
        y += 11

    d.add('<rect x="566" y="68" width="194" height="30" rx="15" '
          'fill="#0e3252" stroke="#65d8ff" stroke-width="1.1"/>')
    pill_fs = 11.0
    pill_w = m["hdr.taxyear"]["w"]
    if pill_w > 178:
        pill_fs = 11.0 * 178 / pill_w
    d.text(663, 87 + pill_fs * 0.06, texts["hdr.taxyear"], pill_fs, 780,
           PALETTE["pill"], anchor="middle")
    d.add('<rect x="37" y="133" width="742" height="5" fill="url(#dl-accent)"/>')

    # ---- flow ---------------------------------------------------------
    y = 157.0
    lead = lambda size: size * ML       # Burmese lines
    elead = lambda size: size * LAT_LEADING     # the English sub-lines

    def clear(size: float, factor: float = 0.95) -> None:
        """Push y down so a first line at `size` clears the previous baseline.

        y is a baseline, so stepping by the *previous* block's leading is not
        enough when the next block is set larger: the title would ride up into
        the kicker above it. This is what stops that.
        """
        nonlocal y
        y = max(y, d.last_y + size * ML * factor)

    clear(fs["kicker"])
    for ln in lines("ttl.kicker"):
        d.text(408, y, ln, fs["kicker"], 780, PALETTE["blue"], anchor="middle")
        y += lead(fs["kicker"])
    y += 10 * S

    clear(fs["title"], 0.98)
    for ln in lines("ttl.title"):
        d.text(408, y, ln, fs["title"], 780, PALETTE["ink"], anchor="middle")
        y += fs["title"] * 1.28
    y += 2
    d.add('<rect x="333" y="%.2f" width="150" height="2.5" '
          'fill="url(#dl-accent)"/>' % y)
    y += 15 * S

    clear(fs["sub"])
    for ln in lines("ttl.sub"):
        d.text(408, y, ln, fs["sub"], 520, PALETTE["body"], anchor="middle")
        y += lead(fs["sub"])
    y += 12 * S

    clear(fs["salut"])
    d.text(CONTENT_X, y, texts["body.salutation"], fs["salut"], 700,
           PALETTE["ink"])
    y += lead(fs["salut"]) + 2 * S

    clear(fs["intro"])
    for ln in lines("intro"):
        d.text(CONTENT_X, y, ln, fs["intro"], None, PALETTE["body"])
        y += lead(fs["intro"])
    y += 12 * S

    # ---- scope notice box (Burmese edition only) ----------------------
    n_my, n_en = nlines("notice.scope"), nlines("notice.scope.en")
    box_h = (9 * S + n_my * lead(fs["notice"]) + 5 * S
             + n_en * elead(fs["notice_en"]) + 9 * S)
    d.add('<rect x="%.2f" y="%.2f" width="%.2f" height="%.2f" rx="6" '
          'fill="#fff4e2"/>' % (box_x, y, box_w, box_h))
    d.add('<rect x="%.2f" y="%.2f" width="4" height="%.2f" fill="#d97a12"/>'
          % (box_x, y, box_h))
    ty = y + 9 * S + fs["notice"]
    for ln in lines("notice.scope"):
        d.text(box_text_x, ty, ln, fs["notice"], 600, "#7a3d00")
        ty += lead(fs["notice"])
    ty += 5 * S
    for ln in lines("notice.scope.en"):
        d.text(box_text_x, ty, ln, fs["notice_en"], 500, "#8a5a22")
        ty += elead(fs["notice_en"])
    y += box_h + 8 * S

    # ---- READ THIS FIRST box ------------------------------------------
    ch, cb = nlines("callout.head"), nlines("callout.body")
    box2_h = (11 * S + ch * lead(fs["callout_h"]) + 5 * S
              + cb * lead(fs["callout"]) + 11 * S)
    d.add('<rect x="%.2f" y="%.2f" width="%.2f" height="%.2f" rx="6" '
          'fill="#e8f2fc"/>' % (box_x, y, box_w, box2_h))
    d.add('<rect x="%.2f" y="%.2f" width="4" height="%.2f" fill="#2d80ff"/>'
          % (box_x, y, box2_h))
    ty = y + 11 * S + fs["callout_h"]
    for ln in lines("callout.head"):
        d.text(box_text_x, ty, ln, fs["callout_h"], 800, PALETTE["blue"])
        ty += lead(fs["callout_h"])
    ty += 5 * S
    for ln in lines("callout.body"):
        d.text(box_text_x, ty, ln, fs["callout"], 500, PALETTE["ink"])
        ty += lead(fs["callout"])
    y += box2_h + 10 * S

    def section(head_key: str, gap_after: float = 5.0) -> None:
        nonlocal y
        clear(fs["sec"])
        for ln in lines(head_key):
            d.text(CONTENT_X, y, ln, fs["sec"], 800, PALETTE["blue"])
            y += lead(fs["sec"])
        y += gap_after * S

    section("arith.head")
    clear(fs["body"])
    for ln in lines("arith.body"):
        d.text(CONTENT_X, y, ln, fs["body"], None, PALETTE["body"])
        y += lead(fs["body"])
    y += 10 * S

    # ---- table ---------------------------------------------------------
    section("tbl.head", 4.0)
    hdr_lines = max(nlines("tbl.col." + k) for k in COLS)
    hdr_h = 6 * S + hdr_lines * (fs["tbl_h"] * ML) + 4 * S
    row_lines = max(max(nlines("row%d.assume" % i), nlines("row%d.note" % i),
                        nlines("row%d.reduction" % i),
                        nlines("row%d.netcost" % i)) for i in (1, 2, 3, 4))
    # Row height is set by the tallest *column stack*, not by a line count at
    # one pitch. The deductible column carries a value in tbl_val with a note
    # in tbl_note under it, which is taller than two assumption lines; sizing
    # rows off the line count alone clipped the last row's note against the
    # table's bottom rule.
    # The English edition puts 3.5 units above the first cell baseline's font
    # box and 3 below the last ink; 4 * S matches that once the type is scaled.
    pad = 4 * S
    asc = 1.0        # Burmese ink ascent measured at 1.003 em, so the first
                     # baseline sits one font size below the row top

    def stack(i: int) -> float:
        """Depth of the deepest ink in row i, measured from the row top."""
        n_as = nlines("row%d.assume" % i)
        n_no = nlines("row%d.note" % i)
        n_rd = nlines("row%d.reduction" % i)
        n_nc = nlines("row%d.netcost" % i)
        b_assume = (pad + fs["tbl_cell"] * asc
                    + (n_as - 1) * fs["tbl_cell"] * ML + fs["tbl_cell"] * 0.55)
        b_deduct = (pad + fs["tbl_val"] * asc + fs["tbl_val"] * 1.18
                    + (n_no - 1) * fs["tbl_note"] * ML + fs["tbl_note"] * 0.55)
        b_red = (pad + fs["tbl_val"] * asc
                 + (n_rd - 1) * fs["tbl_val"] * ML + fs["tbl_val"] * 0.55)
        b_net = (pad + fs["tbl_val"] * asc
                 + (n_nc - 1) * fs["tbl_val"] * ML + fs["tbl_val"] * 0.55)
        b_gift = pad + fs["tbl_gift"] * asc + fs["tbl_gift"] * 0.55
        return max(b_assume, b_deduct, b_red, b_net, b_gift)

    row_h = max(26 * S, max(stack(i) for i in (1, 2, 3, 4)) + pad)
    tbl_top = y
    tbl_h = hdr_h + 4 * row_h

    d.add('<path d="M %.1f,%.2f a 8,8 0 0 1 8,-8 h %.1f a 8,8 0 0 1 8,8 v %.2f '
          'h -%.1f Z" fill="#0b2137"/>'
          % (box_x, tbl_top + 8, box_w - 16, hdr_h - 8, box_w))
    for i in range(4):
        ry = tbl_top + hdr_h + i * row_h
        if i % 2 == 0:
            d.add('<rect x="%.2f" y="%.2f" width="%.2f" height="%.2f" '
                  'fill="#eaf3fd" opacity="0.55"/>' % (box_x, ry, box_w, row_h))
        d.add('<rect x="%.2f" y="%.2f" width="%.2f" height="0.8" '
              'fill="#dce8f4"/>' % (box_x, ry, box_w))
    d.add('<rect x="%.2f" y="%.2f" width="%.2f" height="1" fill="#b8cadd"/>'
          % (box_x, tbl_top + tbl_h, box_w))
    d.add('<rect x="%.2f" y="%.2f" width="%.2f" height="%.2f" fill="none" '
          'stroke="#cfe0f0" stroke-width="1" rx="8"/>'
          % (box_x, tbl_top, box_w, tbl_h))

    hy0 = tbl_top + 6 * S + fs["tbl_h"]
    for name, (cx, cw) in COLS.items():
        hy = hy0
        for ln in lines("tbl.col." + name):
            d.text(cx, hy, ln, fs["tbl_h"], 800, PALETTE["pale"])
            hy += fs["tbl_h"] * ML

    for i in (1, 2, 3, 4):
        ry = tbl_top + hdr_h + (i - 1) * row_h
        mid = ry + row_h / 2
        # Each column's first baseline sits one of *its own* font sizes below
        # the row top, which is what the row-height model above assumes.
        d.text(COLS["gift"][0], mid + fs["tbl_gift"] * 0.34,
               texts["row%d.gift" % i], fs["tbl_gift"], 800, PALETTE["ink"])
        ay = ry + pad + fs["tbl_cell"]
        for ln in lines("row%d.assume" % i):
            d.text(COLS["assume"][0], ay, ln, fs["tbl_cell"], 500,
                   PALETTE["ink"])
            ay += fs["tbl_cell"] * ML
        base = ry + pad + fs["tbl_val"]
        d.text(COLS["deduct"][0], base, texts["row%d.deduct" % i],
               fs["tbl_val"], 800, PALETTE["ink"])
        ny = base + fs["tbl_val"] * 1.18
        for ln in lines("row%d.note" % i):
            d.text(COLS["deduct"][0], ny, ln, fs["tbl_note"], 500,
                   PALETTE["mute"])
            ny += fs["tbl_note"] * ML
        d.text(COLS["rate"][0], mid + fs["tbl_val"] * 0.34,
               texts["row%d.rate" % i], fs["tbl_val"], 700, PALETTE["ink"])
        ry2 = mid - (nlines("row%d.reduction" % i) - 1) * fs["tbl_val"] * 0.6
        for ln in lines("row%d.reduction" % i):
            d.text(COLS["reduction"][0], ry2 + fs["tbl_val"] * 0.34, ln,
                   fs["tbl_val"], 800, PALETTE["blue"])
            ry2 += fs["tbl_val"] * ML
        ry3 = mid - (nlines("row%d.netcost" % i) - 1) * fs["tbl_val"] * 0.6
        for ln in lines("row%d.netcost" % i):
            d.text(COLS["netcost"][0], ry3 + fs["tbl_val"] * 0.34, ln,
                   fs["tbl_val"], 700, PALETTE["ink"])
            ry3 += fs["tbl_val"] * ML

    y = tbl_top + tbl_h + 10 * S
    for ln in lines("tbl.footnote"):
        d.text(CONTENT_X, y, ln, fs["foot"], 500, PALETTE["mute"])
        y += fs["foot"] * ML
    y += 10 * S

    # ---- ceilings / acknowledgment -------------------------------------
    section("ceil.head")
    clear(fs["ceil"])
    d.text(CONTENT_X, y, texts["ceil.lead"], fs["ceil"], 800, PALETTE["ink"])
    y += lead(fs["ceil"])
    for ln in lines("ceilbody"):
        d.text(CONTENT_X, y, ln, fs["ceil"], None, PALETTE["body"])
        y += lead(fs["ceil"])
    y += 7 * S
    clear(fs["ceil"])
    d.text(CONTENT_X, y, texts["ack.lead"], fs["ceil"], 800, PALETTE["ink"])
    y += lead(fs["ceil"])
    for ln in lines("ackbody"):
        d.text(CONTENT_X, y, ln, fs["ceil"], None, PALETTE["body"])
        y += lead(fs["ceil"])
    y += 10 * S

    section("cannot.head")
    clear(fs["ceil"])
    for ln in lines("cannot.body"):
        d.text(CONTENT_X, y, ln, fs["ceil"], None, PALETTE["body"])
        y += lead(fs["ceil"])
    y += 10 * S

    # ---- signature ------------------------------------------------------
    clear(fs["body"])
    d.text(CONTENT_X, y, texts["sign.closing"], fs["body"], None,
           PALETTE["body"])
    y += lead(fs["body"]) + 3 * S
    clear(fs["sign_org"])
    d.text(CONTENT_X, y, texts["sign.org"], fs["sign_org"], 800, PALETTE["ink"])
    sx = CONTENT_X + m["sign.org"]["w"] + 8
    d.text(sx, y, texts["sign.orgsuffix"], fs["sign_suf"], 550, PALETTE["body"])
    y += lead(fs["sign_org"]) + 7 * S

    # ---- governing language notice --------------------------------------
    # No box. A governing-language clause conventionally sits with the closing
    # matter, and the page has no vertical room to spend on a border. Weight
    # and ink colour carry the prominence instead.
    d.add('<rect x="56" y="%.2f" width="704" height="0.8" fill="#c6d5e4"/>'
          % (y - 7 * S))
    clear(fs["gov"])
    for ln in lines("notice.governing"):
        d.text(CONTENT_X, y, ln, fs["gov"], 700, PALETTE["ink"])
        y += lead(fs["gov"])
    y += 1 * S
    for ln in lines("notice.governing.en"):
        d.text(CONTENT_X, y, ln, fs["gov_en"], 500, PALETTE["mute"])
        y += elead(fs["gov_en"])
    y += 6 * S

    # ---- fine print ------------------------------------------------------
    d.add('<rect x="56" y="%.2f" width="704" height="0.8" fill="#dce8f4"/>'
          % (y - 6 * S))
    clear(fs["fine"])
    for ln in lines("fine.print"):
        d.text(CONTENT_X, y, ln, fs["fine"], 500, PALETTE["body"])
        y += fs["fine"] * ML
    y += 4 * S
    clear(fs["domain"])
    d.text(408, y, texts["footer.domain"], fs["domain"], 750, PALETTE["foot"],
           anchor="middle")
    bottom = y + 4

    if placeholder:
        d.add('<g opacity="0.16" transform="rotate(-30 408 560)">'
              '<text x="408" y="470" font-size="72" font-weight="800" '
              'fill="#c01515" text-anchor="middle" letter-spacing="6">'
              'PLACEHOLDER</text>'
              '<text x="408" y="560" font-size="34" font-weight="800" '
              'fill="#c01515" text-anchor="middle" letter-spacing="3">'
              'LAYOUT PROOF ONLY</text>'
              '<text x="408" y="620" font-size="27" font-weight="700" '
              'fill="#c01515" text-anchor="middle" letter-spacing="2">'
              'TEXT IS NOT A TRANSLATION</text></g>')

    head = (
        '<svg xmlns="http://www.w3.org/2000/svg" width="8.5in" height="11in" '
        'viewBox="0 0 816 1056" role="img" font-family="%s" '
        'aria-label="Burmese edition of the Win’s VPN Inc. donor letter '
        'explaining how the United States federal charitable deduction works, '
        'with worked examples for the 2026 tax year">'
        '<title>Win’s VPN Inc.: What a Donation Is Worth at Tax Time '
        '(Burmese)</title>'
        '<defs>'
        '<linearGradient id="dl-head" x1="0" y1="0" x2="1" y2="1">'
        '<stop offset="0" stop-color="#071a2b"/>'
        '<stop offset="0.55" stop-color="#0a2b47"/>'
        '<stop offset="1" stop-color="#061320"/></linearGradient>'
        '<linearGradient id="dl-accent" x1="0" y1="0" x2="1" y2="0">'
        '<stop offset="0" stop-color="#2d80ff"/>'
        '<stop offset="0.5" stop-color="#62dcff"/>'
        '<stop offset="1" stop-color="#2d80ff"/></linearGradient>'
        '<radialGradient id="dl-paper" cx="0.08" cy="0.03" r="0.55">'
        '<stop offset="0" stop-color="#eef6ff"/>'
        '<stop offset="1" stop-color="#ffffff"/></radialGradient>'
        '<clipPath id="dl-logoclip">'
        '<rect x="50" y="43" width="154.23" height="84" rx="6"/>'
        '</clipPath></defs>' % H.escape(FONT, True))
    svg = head + "".join(d.body) + "</svg>"
    stats = {"scale": S, "bottom": bottom,
             "lines": {k: len(v.get("lines", [""])) for k, v in m.items()},
             "table_row_h": row_h, "hdr_lines": hdr_lines}
    return svg, bottom, stats


def render(svg_path: pathlib.Path, png_path: pathlib.Path,
           tmp: pathlib.Path) -> None:
    wrap = tmp / "render.html"
    wrap.write_text(
        '<!doctype html><meta charset="utf-8">'
        '<style>html,body{margin:0;padding:0;background:#fff}'
        'svg{display:block;width:%dpx;height:%dpx}</style>%s'
        % (OUT_W, OUT_H, svg_path.read_text(encoding="utf-8")),
        encoding="utf-8")
    r = subprocess.run(
        [CHROME, "--headless", "--disable-gpu", "--no-sandbox", "--no-first-run",
         "--hide-scrollbars", "--force-device-scale-factor=1",
         "--virtual-time-budget=15000",
         "--window-size=%d,%d" % (OUT_W, OUT_H),
         "--screenshot=%s" % png_path, "file://%s" % wrap],
        capture_output=True, text=True, timeout=180)
    if not png_path.exists():
        sys.stderr.write(r.stderr[-3000:] + "\n")
        raise SystemExit("screenshot failed")


def to_webp(png: pathlib.Path, out: pathlib.Path, w: int, h: int,
            quality: int) -> None:
    from PIL import Image
    im = Image.open(png).convert("RGB")
    if im.size != (w, h):
        im = im.resize((w, h), Image.LANCZOS)
    out.parent.mkdir(parents=True, exist_ok=True)
    im.save(out, "WEBP", quality=quality, method=6)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--translation", default=None,
                    help="completed translator CSV or JSON")
    ap.add_argument("--placeholder", action="store_true",
                    help="generate Burmese filler instead of reading a "
                         "translation. Never publishable.")
    ap.add_argument("--ratio", type=float, default=1.0,
                    help="placeholder width relative to the English source "
                         "(1.0 = same rendered width, the pessimistic case)")
    ap.add_argument("--final", action="store_true",
                    help="write the production asset names into web/assets/. "
                         "Refused with --placeholder.")
    ap.add_argument("--debug", action="store_true")
    ap.add_argument("--seed", type=int, default=20260803)
    ap.add_argument("--quality", type=int, default=88)
    args = ap.parse_args()

    if args.final and args.placeholder:
        sys.exit("--final and --placeholder together would put filler text at "
                 "the published asset name. Refused.")
    if not args.placeholder and not args.translation:
        sys.exit("give --translation FILE, or --placeholder for a layout proof")
    if not pathlib.Path(CHROME).exists():
        sys.exit("Google Chrome not found at %s" % CHROME)

    pkg = json.loads(PKG.read_text(encoding="utf-8"))
    en = en_block_texts(pkg)

    tmpdir = pathlib.Path(tempfile.mkdtemp(prefix="donor-my-"))
    try:
        if args.placeholder:
            rng = random.Random(args.seed)
            cal_items = [{"key": "mm", "text": "".join(SYLL), "size": 10,
                          "weight": "normal", "width": None, "leading": 16}]
            for s in pkg["segment_list"]:
                cal_items.append({"key": "s" + s["id"], "text": s["source_en"],
                                  "size": 10, "weight": "normal",
                                  "width": None, "leading": 13})
                cal_items.append({"key": "f" + s["id"],
                                  "text": " ".join(s["figures"]) or ".",
                                  "size": 10, "weight": "normal",
                                  "width": None, "leading": 13})
            cal = measure(cal_items, tmpdir, "calib")
            per_cluster = cal["mm"]["w"] / len(SYLL)
            print("calibration at 10px: %.3f px per Burmese cluster"
                  % per_cluster)
            targets = {}
            for s in pkg["segment_list"]:
                if s["kind"] in ("verbatim", "figure"):
                    targets[s["id"]] = s["source_en"]
                else:
                    fw = cal["f" + s["id"]]["w"] if s["figures"] else 0.0
                    targets[s["id"]] = placeholder_for(
                        s["source_en"], cal["s" + s["id"]]["w"], rng,
                        args.ratio, per_cluster, fw)
        else:
            targets = read_targets(pathlib.Path(args.translation))

        if args.placeholder:
            # Write the filler out in the translator's own CSV shape so the
            # checker can be run against it. This is what proves the checker
            # and the builder agree on the file format.
            PROOF.mkdir(parents=True, exist_ok=True)
            dump = PROOF / "donor-letter.my.PLACEHOLDER.csv"
            with dump.open("w", newline="", encoding="utf-8-sig") as fh:
                w = csv.writer(fh)
                w.writerow(["id", "block", "kind", "english_source",
                            "burmese_translation", "figures_that_must_survive",
                            "translator_note"])
                for seg in pkg["segment_list"]:
                    w.writerow([seg["id"], seg["block"], seg["kind"],
                                seg["source_en"], targets[seg["id"]],
                                " ".join(seg["figures"]),
                                "PLACEHOLDER FILLER, NOT A TRANSLATION"])
            print("wrote %s" % dump.relative_to(REPO))

        texts = block_texts(pkg, targets)
        for bid in en:
            texts.setdefault(bid, "")
            if not texts[bid].strip():
                sys.exit("block %s has no text. Run check_translation.py first."
                         % bid)

        # Fit by bisection on the type scale, not by proportional stepping: a
        # proportional step shrinks to nothing as the overage shrinks and stalls
        # a hair above the limit. Bisection finds the *largest* scale that fits,
        # so the type stays as big as the page allows.
        SCALE_MIN = 0.78

        def attempt(sc: float, tag: str):
            svg, bottom, stats = build(sc, texts, en, tmpdir, tag,
                                       args.placeholder)
            print("  fit pass %-8s scale %.4f -> content bottom y=%.1f "
                  "(limit %.0f) %s" % (tag, sc, bottom, BOTTOM_LIMIT,
                                       "fits" if bottom <= BOTTOM_LIMIT
                                       else "over by %.1f"
                                            % (bottom - BOTTOM_LIMIT)))
            if args.debug:
                for k, n in sorted(stats["lines"].items(),
                                   key=lambda kv: -kv[1]):
                    if n > 1:
                        print("        %-24s %2d lines" % (k, n))
                print("        table row height %.1f, header lines %d"
                      % (stats["table_row_h"], stats["hdr_lines"]))
            return svg, bottom, stats

        best = None
        svg, bottom, stats = attempt(1.0, "hi")
        if bottom <= BOTTOM_LIMIT:
            best = (svg, bottom, stats)
        else:
            svg, bottom, stats = attempt(SCALE_MIN, "lo")
            if bottom > BOTTOM_LIMIT:
                sys.exit(
                    "content is %.1f units too tall for one page even at the "
                    "%.0f%% type scale floor.\n"
                    "This is a content problem, not a layout problem. Either "
                    "shorten the Burmese (the two notices this edition adds "
                    "are the only text that is ours to cut), or publish a "
                    "taller page. Do not silently clip."
                    % (bottom - BOTTOM_LIMIT, SCALE_MIN * 100))
            best = (svg, bottom, stats)
            lo, hi = SCALE_MIN, 1.0
            for it in range(9):
                mid = (lo + hi) / 2.0
                svg, bottom, stats = attempt(mid, "b%d" % it)
                if bottom <= BOTTOM_LIMIT:
                    best, lo = (svg, bottom, stats), mid
                else:
                    hi = mid
                if hi - lo < 0.002:
                    break
        svg, bottom, stats = best

        PROOF.mkdir(parents=True, exist_ok=True)
        if args.placeholder:
            svg_out = PROOF / "donor-tax-deduction-letter-my.PLACEHOLDER.svg"
            png_out = PROOF / "donor-tax-deduction-letter-my.PLACEHOLDER.png"
            webp = ASSETS / "donor-tax-deduction-letter-my.PLACEHOLDER.webp"
            thumb = (ASSETS /
                     "donor-tax-deduction-letter-my-thumb.PLACEHOLDER.webp")
        else:
            svg_out = (REPO / "brand" / "donor_recognition" /
                       "donor-tax-deduction-letter-my.svg")
            png_out = PROOF / "donor-tax-deduction-letter-my.png"
            if args.final:
                webp = ASSETS / "donor-tax-deduction-letter-my.webp"
                thumb = ASSETS / "donor-tax-deduction-letter-my-thumb.webp"
            else:
                webp = PROOF / "donor-tax-deduction-letter-my.webp"
                thumb = PROOF / "donor-tax-deduction-letter-my-thumb.webp"

        svg_out.write_text(svg, encoding="utf-8")
        render(svg_out, png_out, tmpdir)
        to_webp(png_out, webp, OUT_W, OUT_H, args.quality)
        to_webp(png_out, thumb, THUMB_W, THUMB_H, args.quality)

        from PIL import Image
        print()
        print("scale used            : %.3f" % stats["scale"])
        print("content bottom        : y=%.1f of %.0f" % (bottom, BOTTOM_LIMIT))
        for p in (svg_out, png_out, webp, thumb):
            extra = ""
            if p.suffix in (".webp", ".png"):
                with Image.open(p) as im:
                    extra = "  %dx%d" % im.size
            print("%-10s %9d bytes  %s%s"
                  % (p.suffix.lstrip("."), p.stat().st_size,
                     p.relative_to(REPO) if REPO in p.parents
                     or str(p).startswith(str(REPO)) else p, extra))
        return 0
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


if __name__ == "__main__":
    raise SystemExit(main())
