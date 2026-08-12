#!/usr/bin/env python3
from __future__ import annotations

import os
import subprocess
import tempfile
from pathlib import Path

root = Path(__file__).resolve().parents[1]
launcher = root / "src" / "aur-security-auditor-launcher"
desktop = (root / "aur-security-auditor.desktop").read_text()
installer = (root / "install.sh").read_text()
uninstaller = (root / "uninstall.sh").read_text()

assert "Exec=/usr/bin/aur-security-auditor-launcher" in desktop
assert "sudo /usr/bin/aur-security-auditor" not in desktop
assert 'src/aur-security-auditor-launcher' in installer
assert '/usr/bin/aur-security-auditor-launcher' in uninstaller

with tempfile.TemporaryDirectory() as td:
    td = Path(td)
    sudo = td / "sudo"
    sudo.write_text("#!/usr/bin/env bash\nprintf 'MOCK_SUDO:%s\\n' \"$*\"\n")
    sudo.chmod(0o755)
    base_env = os.environ.copy()
    base_env.update({
        "PATH": f"{td}:{base_env.get('PATH','')}",
        "TERM": "dumb",
        "NO_COLOR": "1",
        "AUR_SECURITY_AUDITOR_NO_ANIMATION": "1",
        "AUR_SECURITY_AUDITOR_FORCE_UNPRIVILEGED": "1",
    })

    en = subprocess.run(
        [str(launcher), "--version"],
        env={**base_env, "LANG": "en_US.UTF-8", "LC_ALL": ""},
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=True,
    ).stdout
    assert "AUR SECURITY AUDITOR" in en
    assert "requires root privileges" in en
    assert "Security boundary:" in en
    assert "sudo authentication will be requested now" in en
    assert "benötigt für die vollständige Analyse" not in en
    assert "MOCK_SUDO:-- /usr/bin/aur-security-auditor --version" in en

    de = subprocess.run(
        [str(launcher), "--version"],
        env={**base_env, "LANG": "de_DE.UTF-8", "LC_ALL": ""},
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=True,
    ).stdout
    assert "AUR SECURITY AUDITOR" in de
    assert "requires root privileges" in de
    assert "Security boundary:" in de
    assert "sudo authentication will be requested now" in de
    assert "benötigt für die vollständige Analyse" not in de
    assert "Sicherheitsgrenze:" not in de
    assert "MOCK_SUDO:-- /usr/bin/aur-security-auditor --version" in de

print("1.4.7 startup-launcher regression test: OK")
print("  ✓ desktop launch explains root access before sudo")
print("  ✓ terminal startup remains English regardless of system locale")
print("  ✓ non-interactive sessions skip animation cleanly")
