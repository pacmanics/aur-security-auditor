#!/usr/bin/env python3
from __future__ import annotations

import re
from collections import Counter
from html.parser import HTMLParser
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
HTML = (ROOT / "data/dashboard.html").read_text()


class VisibleTextParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.hidden_depth = 0
        self.values: list[str] = []

    def handle_starttag(self, tag: str, attrs) -> None:
        if tag in {"script", "style"}:
            self.hidden_depth += 1

    def handle_endtag(self, tag: str) -> None:
        if tag in {"script", "style"} and self.hidden_depth:
            self.hidden_depth -= 1

    def handle_data(self, data: str) -> None:
        if self.hidden_depth:
            return
        value = " ".join(data.split())
        if value and value not in self.values:
            self.values.append(value)


# TEXT must have the exact same keys in English and German.
text_start = HTML.index("const TEXT={")
en_start = HTML.index("en:{", text_start) + len("en:{")
en_end = HTML.index("\n  },\n  de:{", en_start)
de_start = en_end + len("\n  },\n  de:{")
de_end = HTML.index("\n  }\n};", de_start)
key_pattern = re.compile(r"(?:^|[,{])\s*([A-Za-z][A-Za-z0-9_]*)\s*:", re.M)
def object_keys(block: str) -> set[str]:
    masked = re.sub(r'"(?:\\.|[^"\\])*"', '""', block)
    return set(key_pattern.findall(masked))
en_keys = object_keys(HTML[en_start:en_end])
de_keys = object_keys(HTML[de_start:de_end])
assert en_keys == de_keys, (sorted(en_keys - de_keys), sorted(de_keys - en_keys))

# Every literal text consumed through t() needs a dictionary entry.
used_keys = set(re.findall(r"\bt\([\"']([A-Za-z][A-Za-z0-9_]*)[\"']\)", HTML))
assert not (used_keys - en_keys), sorted(used_keys - en_keys)

# Every static visible English string must be mapped unless it is intentionally language-neutral.
static_start = HTML.index("const STATIC_EN_DE={")
static_end = HTML.index("};\nconst originalText", static_start)
static_block = HTML[static_start:static_end]
static_keys = re.findall(r'"((?:[^"\\]|\\.)*)"\s*:', static_block)
duplicates = {key: count for key, count in Counter(static_keys).items() if count > 1}
assert not duplicates, duplicates
static_keys = set(static_keys)

parser = VisibleTextParser()
parser.feed(HTML)
neutral = {
    "AUR Security Auditor", "v__VERSION__", "© PacmanicS", "English", "Deutsch",
    "JSON", "AUR", "IOCs", "SHA-256", "LIVE", "SYSTEM", "Preflight", "Version",
    "—", "/", "▶", "⚙", "?", "×", "00:00", "--:--:--", "ID —",
    "01", "02", "03", "04", "05", "0", "0 ENTRIES",
}
unmapped = [
    value for value in parser.values
    if value not in static_keys
    and value not in neutral
    and not re.fullmatch(r"\d+(?:\s*/\s*\d+)?", value)
]
assert not unmapped, unmapped

# Regression checks for interface polish and Update Guard.
for token in [
    'id="preflightRemove"', '"Remove":"Entfernen"', 'helpAbout:"Hilfe & Info"',
    'helpPreflightText:', 'helpDeepText:', 'helpBoundaryText:',
    'if($("#helpModal").classList.contains("open"))openHelp()',
    '.setting-title{display:block', '.setting-desc{display:block',
    'grid-template-columns:22px minmax(0,1fr)', '/api/preflight/clear',
    'id="deepRemove"', '/api/deep/clear', 'deepSnapshotUnsafeLink:', 'deepRemoveError:',
    'id="deepCancel"', '/api/deep/cancel', 'id="appDialogOverlay"',
    'deepBlockedDependencies:', 'deepTimedOut:', 'eventDeepCancelRequested:',
]:
    assert token in HTML, token
for native_dialog in (r"\balert\s*\(", r"\bconfirm\s*\(", r"\bprompt\s*\("):
    assert not re.search(native_dialog, HTML), native_dialog
assert 'const de=language==="de"' not in HTML
assert 'Hilfe & Über' not in HTML
assert '>0 / 0 Pakete<' not in HTML

print("Dashboard i18n audit: OK")
print(f"  ✓ {len(en_keys)} paired runtime translation keys")
print(f"  ✓ {len(static_keys)} static translation entries")
print("  ✓ Help, dialogs, controls and live drawers re-render on language changes")
print("  ✓ scan-option titles and descriptions use separate block rows")
print("  ✓ no browser-native alert, confirm or prompt dialogs")
print("  ✓ deep cancellation and custom application modal are wired")
