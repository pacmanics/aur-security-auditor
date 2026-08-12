#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import importlib.machinery
import importlib.util
import json
import os
import tempfile
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
APP = ROOT / "src/aur-security-auditor"


def load_app():
    loader = importlib.machinery.SourceFileLoader("ams_security_features", str(APP))
    spec = importlib.util.spec_from_loader(loader.name, loader)
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module


def test_security_surface(module):
    assert module.core.security_surface_for_path("/etc/sudoers.d/test")["impact"] == "critical"
    assert module.core.security_surface_for_path("/usr/lib/modules/6.0/test.ko.zst")["kind"] == "kernel-module"
    assert module.core.security_surface_for_path("/usr/lib/systemd/system/test.timer")["kind"] == "systemd-timer"
    assert module.core.security_surface_for_path("/usr/bin/normal") is None


def test_source_provenance(module):
    metadata = module.source_document_metadata({
        ".SRCINFO": "source = http://203.0.113.5/payload.tar.gz\nsha256sums = SKIP\n",
        "test.install": "post_install() { echo ok; }\n",
    }, "https://aur.invalid/test.tar.gz", "a" * 64)
    assert metadata["skip_count"] == 1, metadata
    assert metadata["checksum_algorithms"] == ["sha256"], metadata
    assert metadata["direct_ip_sources"], metadata
    assert metadata["insecure_sources"], metadata
    assert metadata["install_files"] == ["test.install"], metadata


def test_elf_analysis(module):
    with tempfile.TemporaryDirectory(prefix="ams-elf-test-") as temp:
        root = Path(temp)
        fake_bin = root / "bin"
        fake_bin.mkdir()
        target = root / "payload"
        target.write_bytes(b"\x7fELF" + b"\x00" * 100_000)
        target.chmod(0o755)
        readelf = fake_bin / "readelf"
        readelf.write_text('''#!/usr/bin/env bash
if [[ "$2" == "-l" ]]; then
cat <<'EOF'
Program Headers:
  Type           Offset   VirtAddr           PhysAddr           FileSiz  MemSiz   Flg Align
  INTERP         0x000001 0x0 0x0 0x10 0x10 R 0x1
      [Requesting program interpreter: /tmp/evil-loader]
  LOAD           0x000000 0x0 0x0 0x100 0x100 RWE 0x1000
  GNU_STACK      0x000000 0x0 0x0 0x000 0x000 RWE 0x10
EOF
else
cat <<'EOF'
Dynamic section:
 0x000000000000001d (RUNPATH)            Library runpath: [/tmp/evil-lib:.]
EOF
fi
''')
        readelf.chmod(0o755)
        getcap = fake_bin / "getcap"
        getcap.write_text(f"#!/usr/bin/env bash\nprintf '%s cap_sys_admin=ep\\n' '{target}'\n")
        getcap.chmod(0o755)
        old_path = os.environ.get("PATH", "")
        os.environ["PATH"] = str(fake_bin) + os.pathsep + old_path
        try:
            findings, _ = module.core.scan_path("elf-test", str(target), True)
        finally:
            os.environ["PATH"] = old_path
        rules = {item.rule for item in findings}
        expected = {"elf-unsafe-interpreter", "elf-wx-segment", "elf-executable-stack", "elf-unsafe-rpath", "file-capabilities"}
        assert expected <= rules, (expected - rules, rules)


def test_delta_and_bundle(module):
    previous = {
        "finished": "2026-08-04T18:00:00+00:00",
        "packages": [{
            "name": "demo", "version": "1.0", "verdict": "review",
            "findings": [{"fingerprint": "a" * 64, "package": "demo", "severity": "medium", "rule": "old", "message": "old", "path": "/old", "confidence": 70, "suppressed": False}],
        }],
        "global_findings": [],
    }
    current = {
        "version": module.VERSION, "schema_version": 2, "hostname": "test", "finished": "2026-08-04T19:00:00+00:00",
        "summary": {"packages": 2, "files_checked": 10},
        "packages": [
            {"name": "demo", "version": "2.0", "verdict": "suspicious", "findings": [{"fingerprint": "b" * 64, "package": "demo", "severity": "high", "rule": "new", "message": "new", "path": "/new", "confidence": 90, "suppressed": False}]},
            {"name": "second", "version": "1", "verdict": "clean", "findings": []},
        ],
        "global_findings": [],
    }
    delta = module.compare_reports(previous, current)
    current["delta"] = delta
    assert delta["summary"]["new_findings"] == 1, delta
    assert delta["summary"]["resolved_findings"] == 1, delta
    assert delta["summary"]["version_changes"] == 1, delta
    assert delta["summary"]["verdict_changes"] == 1, delta
    assert current["packages"][0]["findings"][0]["delta_status"] == "new"
    bundle = module.evidence_bundle(current)
    with tempfile.TemporaryDirectory(prefix="ams-bundle-test-") as temp:
        archive_path = Path(temp) / "evidence.zip"
        archive_path.write_bytes(bundle)
        with zipfile.ZipFile(archive_path) as archive:
            assert set(archive.namelist()) == {"report.json", "README.txt", "manifest.sha256"}
            report = archive.read("report.json")
            readme = archive.read("README.txt")
            manifest = archive.read("manifest.sha256").decode()
            assert hashlib.sha256(report).hexdigest() in manifest
            assert hashlib.sha256(readme).hexdigest() in manifest
            parsed = json.loads(report)
            assert parsed["delta"]["summary"]["new_findings"] == 1


def main():
    module = load_app()
    test_security_surface(module)
    test_source_provenance(module)
    test_elf_analysis(module)
    test_delta_and_bundle(module)
    print("Security feature tests: OK")
    print("  ✓ privileged security-surface classification")
    print("  ✓ AUR source provenance extraction")
    print("  ✓ ELF hardening, RPATH, interpreter and capability analysis")
    print("  ✓ baseline delta comparison")
    print("  ✓ evidence ZIP and SHA-256 manifest")


if __name__ == "__main__":
    main()
