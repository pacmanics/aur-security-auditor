#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import importlib.machinery
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
APP = ROOT / "src/aur-security-auditor"
HTML = (ROOT / "data/dashboard.html").read_text()

loader = importlib.machinery.SourceFileLoader("auditor", str(APP))
spec = importlib.util.spec_from_loader("auditor", loader)
assert spec and spec.loader
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)

documents = {
    "PKGBUILD": """
pkgname=demo
pkgver=1
source=(\"https://upstream.invalid/${pkgver}.tar.gz\")
# local dashboard example: http://127.0.0.1:9999/api
""",
    ".SRCINFO": """
pkgbase = demo
\tpkgver = 1
\tsource = https://upstream.invalid/demo-1.tar.gz
""",
    "README.md": "Docs at https://docs.invalid and http://localhost:8080/",
}
meta = module.source_document_metadata(documents)
assert meta["source_urls"] == ["https://upstream.invalid/demo-1.tar.gz"], meta
assert meta["source_hosts"] == ["upstream.invalid"], meta

# If a local address is genuinely declared as a package source, it remains
# visible and can be rated instead of being silently hidden.
local_declared = module.source_document_metadata({
    ".SRCINFO": "pkgbase = demo\n\tsource = http://127.0.0.1/payload\n"
})
assert local_declared["source_urls"] == ["http://127.0.0.1/payload"], local_declared
assert local_declared["direct_ip_sources"] == ["http://127.0.0.1/payload"], local_declared

malformed = module.source_document_metadata({
    ".SRCINFO": "pkgbase = demo\n\tsource = http://[IP\n\tsource = https://[IP\n\tsource = https://valid.example/file.tar.gz\n"
})
assert malformed["source_urls"] == ["https://valid.example/file.tar.gz"], malformed

saved_report = {
    "provenance": {
        "source_urls": ["http://[IP", "https://[IP", "https://valid.example/file.tar.gz"],
        "source_hosts": ["stale.invalid"],
        "insecure_sources": ["http://[IP"],
        "direct_ip_sources": [],
    }
}
assert module._sanitize_report_source_provenance(saved_report) is True
assert saved_report["provenance"]["source_urls"] == ["https://valid.example/file.tar.gz"]
assert saved_report["provenance"]["source_hosts"] == ["valid.example"]

for token in [
    'api("/api/scan/cancel",{method:"POST",body:{}})',
    '.filter(displayableSourceUrl).slice(0,10)',
    '.filter(displayableSourceUrl).slice(0,12)',
    'function displayableSourceUrl',
    'id="preflightExport"', 'id="guardExport"', 'id="deepExport"',
    'id="packageExport"', 'function downloadJsonFile',
    'const packageDetailCache=new Map()', 'renderPackageDetails(name,cached.pkg,cached.graph)',
    'Date.now()-10*60*1000', 'aboutIntroTitle:',
    'https://altbox.de/', 'K=pacmanics&SeB=m',
    'active-aur-malicious-packages-incident', 'Arch_User_Repository',
]:
    assert token in HTML, token

assert 'events.slice(-90)' not in HTML
assert 'warnings.slice(-12)' not in HTML
assert 'await poll();await openPackage(selectedPackage)' not in HTML
assert 'urls.update(core.URL_RE.findall(text))' not in APP.read_text()

print("1.4.4 release-polish regression test: OK")
print("  ✓ source list is limited to declared package sources")
print("  ✓ expanded .SRCINFO sources take precedence over unresolved PKGBUILD URLs")
print("  ✓ package, preflight, deep-scan and Update Guard details are exportable")
print("  ✓ package details use a client cache and update immediately after suppression")
print("  ✓ activity log shows the complete rolling ten-minute window")
print("  ✓ Help & About includes product background and maintainer links")
