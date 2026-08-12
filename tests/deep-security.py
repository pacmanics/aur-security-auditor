#!/usr/bin/env python3
from __future__ import annotations

import importlib.machinery
import importlib.util
import io
import json
import os
import tarfile
import tempfile
import threading
import time
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
APP = ROOT / "src/aur-security-auditor"
loader = importlib.machinery.SourceFileLoader("ams_deep_test", str(APP))
spec = importlib.util.spec_from_loader(loader.name, loader)
module = importlib.util.module_from_spec(spec)
loader.exec_module(module)


def snapshot(package: str, link_target: str = "shared.conf", special: bool = False) -> bytes:
    payload = b"pkgname=deep-demo\npkgver=1\npkgrel=1\narch=('any')\npackage(){ :; }\n"
    shared = b"safe in-tree link target\n"
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as archive:
        root = tarfile.TarInfo(package)
        root.type = tarfile.DIRTYPE
        root.mode = 0o755
        archive.addfile(root)
        info = tarfile.TarInfo(f"{package}/PKGBUILD")
        info.size = len(payload)
        info.mode = 0o644
        archive.addfile(info, io.BytesIO(payload))
        shared_info = tarfile.TarInfo(f"{package}/shared.conf")
        shared_info.size = len(shared)
        shared_info.mode = 0o644
        archive.addfile(shared_info, io.BytesIO(shared))
        link = tarfile.TarInfo(f"{package}/shared-link.conf")
        link.type = tarfile.SYMTYPE
        link.linkname = link_target
        link.mode = 0o777
        archive.addfile(link)
        if special:
            fifo = tarfile.TarInfo(f"{package}/forbidden.fifo")
            fifo.type = tarfile.FIFOTYPE
            archive.addfile(fifo)
    return buffer.getvalue()


with tempfile.TemporaryDirectory(prefix="ams-deep-test-") as temp:
    tmp = Path(temp)
    builder = tmp / "fake-clean-chroot-build"
    builder.write_text(r'''#!/usr/bin/env python3
import io, tarfile
from pathlib import Path
assert Path('shared-link.conf').is_symlink()
assert Path('shared-link.conf').read_text() == 'safe in-tree link target\n'
out = Path.cwd() / "deep-demo-1.0-1-any.pkg.tar.gz"
with tarfile.open(out, "w:gz") as archive:
    files = {
        ".PKGINFO": (b"pkgname = deep-demo\npkgver = 1.0-1\n", 0o644),
        ".BUILDINFO": (b"buildtool = devtools\n", 0o644),
        "usr/bin/deep-demo": (b"#!/bin/sh\necho demo\n", 0o4755),
        "usr/lib/systemd/system/deep-demo.service": (b"[Service]\nExecStart=/usr/bin/deep-demo\n", 0o644),
    }
    for name, (payload, mode) in files.items():
        info = tarfile.TarInfo(name)
        info.size = len(payload)
        info.mode = mode
        archive.addfile(info, io.BytesIO(payload))
print("fake clean chroot build complete")
''')
    builder.chmod(0o755)

    module.preflight_analysis = lambda target, include_history=True: {
        "tool": "AUR Security Auditor", "version": module.VERSION, "mode": "preflight",
        "package": "deep-demo", "input": str(target), "risk": "minimal",
        "confidence": "medium", "confidence_score": 72,
        "coverage": {"completed": 6, "enabled": 6, "checks": []},
        "findings": [], "summary": {"findings": 0}, "documents": [],
    }
    raw = snapshot("deep-demo")
    module._download_aur_snapshot_bytes = lambda package: (
        raw,
        {"snapshot_url": "https://aur.archlinux.org/cgit/aur.git/snapshot/deep-demo.tar.gz",
         "snapshot_sha256": module.hashlib.sha256(raw).hexdigest(), "snapshot_bytes": len(raw)},
    )
    os.environ["AUR_SECURITY_AUDITOR_DEEP_BUILDER"] = str(builder)
    os.environ["AUR_SECURITY_AUDITOR_DEEP_ALLOW_UNPRIVILEGED"] = "1"

    safe_extract = tmp / "safe-extract"
    module._safe_extract_deep_snapshot(raw, "deep-demo", safe_extract)
    assert (safe_extract / "shared-link.conf").is_symlink()
    assert (safe_extract / "shared-link.conf").read_text() == "safe in-tree link target\n"

    for unsafe_target in ("/etc/passwd", "../../etc/passwd"):
        try:
            module._safe_extract_deep_snapshot(snapshot("deep-demo", unsafe_target), "deep-demo", tmp / ("bad-" + str(abs(hash(unsafe_target)))))
        except RuntimeError as exc:
            assert "unsicheren Linkeintrag" in str(exc), exc
        else:
            raise AssertionError(f"unsafe symlink accepted: {unsafe_target}")

    try:
        module._safe_extract_deep_snapshot(snapshot("deep-demo", special=True), "deep-demo", tmp / "bad-special")
    except RuntimeError as exc:
        assert "Spezialeintrag" in str(exc), exc
    else:
        raise AssertionError("special tar entry accepted")

    report = module.deep_analysis("deep-demo", include_history=False)
    assert report["status"] == "complete", json.dumps(report, indent=2)
    assert report["summary"]["artifacts"] == 1, report["summary"]
    assert report["summary"]["suid"] == 1, report["summary"]
    assert report["risk"] in {"high", "critical"}, report["risk"]
    assert any(item["rule"] == "deep-suid-file" for item in report["findings"]), report["findings"]
    assert report["safety"]["host_install_performed"] is False

    bundle = module.deep_evidence_bundle(report)
    with zipfile.ZipFile(io.BytesIO(bundle)) as archive:
        assert {"deep-report.json", "build.log", "namcap.txt", "manifest.sha256"} <= set(archive.namelist())

    code, args = module.deep_error_descriptor(RuntimeError("AUR-Snapshot enthält einen unsicheren Linkeintrag"))
    assert code == "deepSnapshotUnsafeLink" and args == {}, (code, args)
    code, args = module.deep_error_descriptor(module.DeepBuildError("Clean-Chroot-Build fehlgeschlagen (Exit 17)"))
    assert code == "deepBuildExit" and args == {"exit": "17"}, (code, args)

    dependency_log = """==> ERROR: 'pacman' failed to install missing dependencies.
==> Missing dependencies:
  -> python312
  -> example-aur-dep>=2
==> ERROR: Could not resolve all dependencies.
"""
    status, failure_code, failure_args, failure_message = module._classify_deep_build(255, dependency_log, [])
    assert status == "blocked", (status, failure_code, failure_args)
    assert failure_code == "deepBlockedDependencies", failure_code
    assert failure_args == {"dependencies": "example-aur-dep, python312", "count": 2}, failure_args
    assert "python312" in failure_message, failure_message

    sleeper = tmp / "cancellable-builder"
    sleeper.write_text("#!/usr/bin/env python3\nimport time\ntime.sleep(30)\n")
    sleeper.chmod(0o755)
    cancel = threading.Event()
    timer = threading.Timer(0.25, cancel.set)
    timer.daemon = True
    timer.start()
    cancel_started = time.monotonic()
    try:
        module._run_deep_command([str(sleeper)], tmp, timeout=10, cancel_event=cancel)
    except module.DeepCancelled:
        pass
    else:
        raise AssertionError("deep build ignored cancellation")
    finally:
        timer.cancel()
    assert time.monotonic() - cancel_started < 5, "cancelled build process was not terminated promptly"

    os.environ["AUR_SECURITY_AUDITOR_HOME"] = str(tmp / "manager-home")
    manager = module.Manager(module.paths())
    latest = manager.p["state"] / "latest-deep.json"
    module.atomic_json(latest, report)
    manager.deep_state.update({"status": "failed", "package": "deep-demo", "error": "test", "report": report})
    ok, _ = manager.clear_deep()
    assert ok is True and manager.deep_state["status"] == "idle"
    assert manager.deep_state["report"] is None and not latest.exists()

print("Deep scan security test: OK")
print("  ✓ safe in-tree AUR symlink support")
print("  ✓ escaping links and special entries rejected")
print("  ✓ clean-chroot runner integration")
print("  ✓ built archive inventory")
print("  ✓ SUID detection and risk correlation")
print("  ✓ no host installation")
print("  ✓ deep evidence bundle")
print("  ✓ stable localized deep-error codes")
print("  ✓ unresolved dependencies become an actionable BLOCKED result")
print("  ✓ active build process group can be cancelled")
print("  ✓ failed deep results can be removed")
