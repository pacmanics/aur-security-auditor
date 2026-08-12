#!/usr/bin/env python3
from __future__ import annotations

import importlib.machinery
import importlib.util
import json
import os
import stat
import tempfile
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
APP = ROOT / "src/aur-security-auditor"


def load_app():
    loader = importlib.machinery.SourceFileLoader("ams_hardening_test", str(APP))
    spec = importlib.util.spec_from_loader(loader.name, loader)
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module


def mode(path: Path) -> int:
    return stat.S_IMODE(path.stat().st_mode)


def main() -> int:
    module = load_app()
    with tempfile.TemporaryDirectory(prefix="ams-hardening-") as temp:
        root = Path(temp)
        home = root / "home"
        home.mkdir(mode=0o755)
        old_home = os.environ.get("AUR_SECURITY_AUDITOR_HOME")
        os.environ["AUR_SECURITY_AUDITOR_HOME"] = str(home)
        try:
            paths = module.paths()
            for name in ("config", "cache", "state", "reports"):
                assert mode(paths[name]) == 0o700, (name, oct(mode(paths[name])))

            module.atomic_json(paths["approvals"], {"schema_version": 1, "packages": {}})
            assert mode(paths["approvals"]) == 0o600
            assert json.loads(paths["approvals"].read_text())["schema_version"] == 1

            victim = root / "victim.txt"
            victim.write_text("unchanged")
            link = paths["state"] / "link.json"
            link.symlink_to(victim)
            module.atomic_json(link, {"safe": True})
            assert victim.read_text() == "unchanged"
            assert not link.is_symlink()
            assert json.loads(link.read_text()) == {"safe": True}
            assert mode(link) == 0o600

            public_parent = root / "existing-output"
            public_parent.mkdir(mode=0o755)
            output = public_parent / "report.json"
            module.private_text(output, "{}\n")
            assert mode(public_parent) == 0o755
            assert mode(output) == 0o600

            evidence = root / "deep-evidence.zip"
            report = {
                "package": "fixture",
                "risk": "low",
                "build": {"tool": "fixture", "duration_seconds": 0.1, "log": "build ok"},
                "namcap": {"output": "namcap ok"},
                "summary": {"artifacts": 1, "files": 2, "suid": 0, "sgid": 0, "findings": 0},
            }
            original = module.deep_analysis
            module.deep_analysis = lambda *args, **kwargs: report
            try:
                rc = module.deep_cli(["fixture", "--evidence", str(evidence)])
            finally:
                module.deep_analysis = original
            assert rc == 0
            assert mode(evidence) == 0o600
            with zipfile.ZipFile(evidence) as archive:
                assert {"deep-report.json", "build.log", "namcap.txt", "manifest.sha256"} <= set(archive.namelist())
        finally:
            if old_home is None:
                os.environ.pop("AUR_SECURITY_AUDITOR_HOME", None)
            else:
                os.environ["AUR_SECURITY_AUDITOR_HOME"] = old_home

        bad_home = root / "bad-home"
        (bad_home / ".config").mkdir(parents=True)
        redirected = root / "redirected"
        redirected.mkdir(mode=0o755)
        (bad_home / ".config/aur-security-auditor").symlink_to(redirected, target_is_directory=True)
        os.environ["AUR_SECURITY_AUDITOR_HOME"] = str(bad_home)
        try:
            try:
                module.paths()
                raise AssertionError("symlinked private data path was accepted")
            except RuntimeError as exc:
                assert "Symlink" in str(exc)
            assert mode(redirected) == 0o755
        finally:
            if old_home is None:
                os.environ.pop("AUR_SECURITY_AUDITOR_HOME", None)
            else:
                os.environ["AUR_SECURITY_AUDITOR_HOME"] = old_home

    print("Persistence and CLI hardening test: OK")
    print("  ✓ private runtime directories and files")
    print("  ✓ atomic replacement does not follow output symlinks")
    print("  ✓ symlinked private data directories are rejected")
    print("  ✓ explicit output parent permissions are preserved")
    print("  ✓ documented deep --evidence option")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
