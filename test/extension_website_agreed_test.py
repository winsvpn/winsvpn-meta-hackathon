"""Static website acceptance checks from the agreed extension rows."""
from pathlib import Path
import json
import re

ROOT = Path(__file__).resolve().parents[1]


def test_download_and_tracking_removals():
    text = (ROOT / "web/index.html").read_text()
    for forbidden in ['href="https://play.google.com', "apps.apple.com/app/wins-vpn", "safari.zip", "trackWinsEvent", "WINS_TRACKING", "googletagmanager", "connect.facebook", "isCensoredNetwork", "censorshipBypass", "i18n/major.json"]:
        assert forbidden not in text


def test_locale_split_and_video_user_gesture():
    text = (ROOT / "web/index.html").read_text()
    tag = re.search(r'<video\b[^>]*id="demoVideo"[^>]*>', text).group(0)
    assert "autoplay" not in tag and 'preload="none"' in tag
    assert "IntersectionObserver" not in text
    codes = set(re.findall(r'"([a-z]{2}(?:-[A-Z]{2})?)"', re.search(r'const bundledLocales = new Set\(\[(.*?)\]\)', text, re.S).group(1)))
    files = {p.stem for p in (ROOT / "web/i18n/locales").glob("*.json")}
    assert codes == files - {"en"}
    source = json.loads((ROOT / "web/i18n/major.json").read_text())
    for code, table in source.items():
        assert json.loads((ROOT / f"web/i18n/locales/{code}.json").read_text()) == table
    assert "i18n/major.json" in (ROOT / "web/.assetsignore").read_text().splitlines()


def test_download_start_is_independent_and_checkout_is_closed():
    text = (ROOT / "web/index.html").read_text()
    assert text.index("      loadDownloadManifest();") < text.index("      loadI18nAssets().then(")
    assert 'if (!expectedOrigin) throw new Error("invalid_checkout_url");' in text
    assert "safeStoredLanguage() || normalizeLocale(navigator.language)" in text
    assert "element.closest(\"[translate='no']\")" in text
    assert text.count("element.closest(\"[translate='no']\")") == 2
    assert 'codeElement.setAttribute("translate", "no")' in text


def test_mirror_authority_and_crypto_accessibility():
    text = (ROOT / "web/index.html").read_text()
    origins = json.loads(re.search(r'const trustedSiteOrigins = Object.freeze\((\[[^\]]+\])\)', text).group(1))
    mirrors = [line.strip() for line in (ROOT / "web/mirrors.txt").read_text().splitlines() if line.strip() and not line.startswith("#")]
    assert origins == ["https://winsvpn.org"] + mirrors
    assert 'href="https://winsvpn.org/pay/' not in text
    assert 'role="tablist"' not in text
    assert 'b.setAttribute("aria-pressed"' in text
    assert "modalOpener = document.activeElement" in text
    assert "modalOpener?.focus()" in text
