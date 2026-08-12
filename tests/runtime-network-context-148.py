#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CORE = ROOT / "src/core.py"

spec = importlib.util.spec_from_file_location("asa_runtime_network_core", CORE)
if spec is None or spec.loader is None:
    raise RuntimeError(f"Could not load {CORE}")
module = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = module
spec.loader.exec_module(module)

sample = (
    'tcp ESTAB 0 0 192.168.0.244:39320 142.250.27.188:5228 '
    'users:(("chrome",pid=3806,fd=34),("chrome",pid=3807,fd=35))\n'
    'udp ESTAB 0 0 192.168.0.244:39320 142.250.27.188:5228 '
    'users:(("chrome",pid=3808,fd=36))\n'
    'tcp ESTAB 0 0 127.0.0.1:59628 127.0.0.1:6379 '
    'users:(("python",pid=1148,fd=13),("python",pid=1147,fd=13),'
    '("python",pid=1146,fd=13))\n'
)

orig_geteuid = module.os.geteuid
orig_readlink = module.os.readlink
orig_run = module.run
orig_owner_of = module.owner_of

try:
    module.os.geteuid = lambda: 0
    module.os.readlink = lambda path: (
        "/opt/google/chrome/chrome"
        if "380" in str(path)
        else "/usr/bin/python3.12"
    )
    module.run = lambda cmd, timeout=30: subprocess.CompletedProcess(
        cmd, 0, sample, ""
    )
    module.owner_of = lambda target: {
        "/opt/google/chrome/chrome": "google-chrome",
        "/usr/bin/python3.12": "python312",
    }.get(target, "")

    findings = module.live_connections({"google-chrome", "python312"})
finally:
    module.os.geteuid = orig_geteuid
    module.os.readlink = orig_readlink
    module.run = orig_run
    module.owner_of = orig_owner_of

assert len(findings) == 3, findings

chrome = [item for item in findings if item.package == "google-chrome"]
python = next(item for item in findings if item.package == "python312")

assert len(chrome) == 2, chrome
assert all(item.message.endswith("142.250.27.188:5228") for item in chrome), chrome
assert all(not item.message.endswith("192.168.0.244:39320") for item in chrome), chrome
assert {item.evidence.split()[0] for item in chrome} == {"tcp", "udp"}, chrome
assert python.message.endswith("127.0.0.1:6379"), python

assert sum(item.package == "python312" for item in findings) == 1, findings
assert sum(item.package == "google-chrome" for item in findings) == 2, findings
assert all(item.rule == "live-outbound-connection" for item in findings), findings

print("1.4.8 runtime network-context regression test: OK")
print("  ✓ peer endpoint is parsed from the correct ss column")
print("  ✓ local endpoint is never mislabeled as the remote peer")
print("  ✓ duplicate PID records within one socket row collapse to one context item")
print("  ✓ separate socket rows remain individually visible")
