#!/usr/bin/env python3
from __future__ import annotations

import importlib.machinery
import importlib.util
import io
import json
import os
import shutil
import subprocess
import tarfile
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
APP = ROOT / "src/aur-security-auditor"
loader = importlib.machinery.SourceFileLoader("ams_update_guard_test", str(APP))
spec = importlib.util.spec_from_loader(loader.name, loader)
module = importlib.util.module_from_spec(spec)
loader.exec_module(module)


def write_package(root: Path, version: str = "1.0", host: str = "example.org", checksum: str = "a" * 64, install_script: bool = False) -> None:
    root.mkdir(parents=True, exist_ok=True)
    install_line = "install=demo.install\n" if install_script else ""
    (root / "PKGBUILD").write_text(
        f"pkgname=guard-demo\npkgver={version}\npkgrel=1\narch=('any')\n"
        f"source=('https://{host}/guard-demo-{version}.tar.gz')\n"
        f"sha256sums=('{checksum}')\n{install_line}package() {{ :; }}\n"
    )
    (root / ".SRCINFO").write_text(
        f"pkgbase = guard-demo\n\tpkgver = {version}\n\tpkgrel = 1\n"
        f"\tsource = https://{host}/guard-demo-{version}.tar.gz\n"
        f"\tsha256sums = {checksum}\n"
        + ("\tinstall = demo.install\n" if install_script else "")
        + "pkgname = guard-demo\n"
    )
    if install_script:
        (root / "demo.install").write_text("post_install() { systemctl enable guard-demo.service; }\n")
        (root / "guard-demo.service").write_text("[Service]\nExecStart=/usr/bin/guard-demo\n")


with tempfile.TemporaryDirectory(prefix="ams-update-guard-") as temp:
    base = Path(temp)
    home = base / "home"
    package_dir = base / "package"
    os.environ["AUR_SECURITY_AUDITOR_HOME"] = str(home)

    write_package(package_dir)
    first = module.preflight_analysis(str(package_dir), include_history=False)
    assert first["input_type"] == "local-directory", first["input_type"]
    assert first["package"] == "guard-demo", first["package"]
    assert first["guard_signature"]["version"] == "1.0-1", first["guard_signature"]
    assert first["safety"]["pkgbuild_executed"] is False
    assert first["safety"]["archive_extracted_to_disk"] is False

    p = module.paths()
    initial_guard = module.attach_update_guard(first, p)["update_guard"]
    assert initial_guard["baseline_available"] is False
    approval = module.approve_report(first, p)
    assert approval["package"] == "guard-demo"

    unchanged = module.attach_update_guard(module.preflight_analysis(str(package_dir)), p)["update_guard"]
    assert unchanged["baseline_available"] is True
    assert unchanged["exact_match"] is True
    assert unchanged["risk"] == "minimal"
    assert unchanged["summary"]["changes"] == 0

    write_package(package_dir, version="2.0", host="downloads.example.net", checksum="SKIP", install_script=True)
    changed_report = module.attach_update_guard(module.preflight_analysis(str(package_dir)), p)
    guard = changed_report["update_guard"]
    kinds = {item["kind"] for item in guard["changes"]}
    assert guard["exact_match"] is False
    assert guard["risk"] in {"high", "critical"}, guard
    assert "version-changed" in kinds
    assert "source-host-added" in kinds
    assert "skip-increased" in kinds
    assert "install-script-added" in kinds
    assert guard["summary"]["changed_documents"] >= 2
    assert guard["summary"]["new_findings"] >= 1

    approvals = module.load_approvals(p)
    assert "guard-demo" in approvals["packages"]
    assert module.remove_approval("guard-demo", p) is True
    assert module.load_approvals(p)["packages"] == {}

    # Local archive analysis stays in memory and rejects traversal paths.
    safe_archive = base / "guard-demo.tar.gz"
    with tarfile.open(safe_archive, "w:gz") as archive:
        for source in [package_dir / "PKGBUILD", package_dir / ".SRCINFO"]:
            payload = source.read_bytes()
            info = tarfile.TarInfo(f"guard-demo/{source.name}")
            info.size = len(payload)
            archive.addfile(info, io.BytesIO(payload))
    archive_report = module.preflight_analysis(str(safe_archive))
    assert archive_report["input_type"] == "local-archive"
    assert archive_report["safety"]["archive_extracted_to_disk"] is False

    if shutil.which("zstd"):
        plain_tar = base / "guard-demo.tar"
        zstd_archive = base / "guard-demo.tar.zst"
        with tarfile.open(plain_tar, "w:") as archive:
            for source in [package_dir / "PKGBUILD", package_dir / ".SRCINFO"]:
                payload = source.read_bytes()
                info = tarfile.TarInfo(f"guard-demo/{source.name}")
                info.size = len(payload)
                archive.addfile(info, io.BytesIO(payload))
        subprocess.run(["zstd", "-q", "-f", str(plain_tar), "-o", str(zstd_archive)], check=True)
        zstd_report = module.preflight_analysis(str(zstd_archive))
        assert zstd_report["input_type"] == "local-archive"
        assert zstd_report["safety"]["archive_extracted_to_disk"] is False

    bad_archive = base / "bad.tar.gz"
    with tarfile.open(bad_archive, "w:gz") as archive:
        payload = b"pkgname=bad\n"
        info = tarfile.TarInfo("../PKGBUILD")
        info.size = len(payload)
        archive.addfile(info, io.BytesIO(payload))
    try:
        module.preflight_analysis(str(bad_archive))
    except RuntimeError as exc:
        assert "unsicheren Dateipfad" in str(exc)
    else:
        raise AssertionError("Traversal archive was accepted")

print("Update Guard and local-source test: OK")
print("  ✓ exact-version approval bound to snapshot and file hashes")
print("  ✓ semantic source, checksum, install-script and finding diff")
print("  ✓ local directory and gzip/zstd archive inspection without execution")
print("  ✓ archive traversal rejection")
print("  ✓ approval removal")
