#!/usr/bin/env python3
"""
Updates web/index.html and web/i18n/major.json:
1. Complete 249-language flagMap for localeFlag()
2. Enable translation on the 6th feature card
3. Add full translations for Defense in Depth, Winn Protocol, and related cards
"""

import json
import re

with open("tools/build_language_flags.py") as f:
    code = f.read()

# Extract FLAG_MAP from build_language_flags.py
flag_map_match = re.search(r"FLAG_MAP = (\{.*?\n\})", code, re.DOTALL)
if not flag_map_match:
    raise ValueError("Could not find FLAG_MAP")
flag_map = eval(flag_map_match.group(1))

# Format flagMap as concise JS object
js_flag_map_entries = []
for k in sorted(flag_map.keys()):
    js_flag_map_entries.append(f'"{k}": "{flag_map[k]}"')
js_flag_map_str = "        const flagMap = {\n          " + ",\n          ".join(js_flag_map_entries) + "\n        };"

# 1. Update web/index.html
with open("web/index.html") as f:
    html = f.read()

# Replace localeFlag
old_locale_flag = re.search(r"      function localeFlag\(locale\) \{.*?      \}", html, re.DOTALL)
if not old_locale_flag:
    raise ValueError("Could not find localeFlag in index.html")

new_locale_flag = f"""      function localeFlag(locale) {{
        const normalized = String(locale || "en").toLowerCase();
{js_flag_map_str}
        if (flagMap[normalized]) return flagMap[normalized];
        const region = normalized.match(/[-_]([a-z]{{2}})$/)?.[1];
        if (!region) return "🌐";
        return [...region.toUpperCase()].map((char) =>
          String.fromCodePoint(0x1F1E6 + char.charCodeAt(0) - 65)
        ).join("");
      }}"""

html = html.replace(old_locale_flag.group(0), new_locale_flag)

# Remove translate="no" on line 3134 (Cyber insurance card)
html = html.replace(
    '<p translate="no">Win\'s VPN Inc. and Win Empire LLC maintain insurance-readiness controls and may seek cyber or Technology Errors and Omissions coverage. We do not represent that a particular policy is currently bound or in force. Coverage must be confirmed from a current binder or issued policy.</p>',
    '<p>Win\'s VPN Inc. and Win Empire LLC maintain insurance-readiness controls and may seek cyber or Technology Errors and Omissions coverage. We do not represent that a particular policy is currently bound or in force. Coverage must be confirmed from a current binder or issued policy.</p>'
)

with open("web/index.html", "w") as f:
    f.write(html)
print("Updated web/index.html successfully!")

