# AUR Security Auditor 1.4.8

Explainable security analysis for Arch Linux AUR and other foreign packages before installation, after installation and when package sources change.

The application opens a browser dashboard, remains idle until the user starts an analysis and stores reports, suppressions, scan baselines and reviewed package versions in the invoking user's profile.

## Installation on CachyOS / Arch Linux

```bash
cd ~/Downloads
sha256sum -c aur-security-auditor-1.4.8.sha256
tar -xzf aur-security-auditor-1.4.8.tar.gz
cd aur-security-auditor-1.4.8
sudo ./install.sh
```

Start from the application menu to get the privileged-access explanation before sudo authentication, or start directly from a terminal:

```bash
sudo aur-security-auditor
```

The application-menu entry runs `/usr/bin/aur-security-auditor-launcher`. It displays a short English security banner explaining why root privileges are requested and then invokes `/usr/bin/aur-security-auditor` through sudo. Terminal and CLI operation remain English regardless of the system locale. German is selected only inside the browser dashboard. Animation is disabled automatically when no interactive terminal is attached.

## What changed in 1.4.8

Version 1.4.8 hardens context-aware verdicts and reduces false positives without weakening confirmed malware detection:

- LOW-only advisory findings now keep the package verdict CLEAN, while MEDIUM, HIGH and CRITICAL evidence still escalate to REVIEW, SUSPICIOUS and THREAT
- behavioral correlations require local executable context instead of unrelated signals elsewhere in the same large file
- documentation, tests, CI files, wordlists, package metadata and foreign-platform binary strings stay non-actionable unless stronger evidence exists
- JavaScript package-manager help/error text is separated from actual child-process, spawn, execa, Bun or Deno execution
- exact malware hashes, confirmed malicious package/dependency names and executable confirmed C2 context remain hard indicators
- the auditor can safely scan its own signature databases, regex definitions and self-test vectors without self-incrimination, while adjacent real payload logic remains detectable
- insecure HTTP source severity is bound to the checksum of each concrete source instead of borrowing verification strength from another source
- HTTP sources with an aligned strong checksum and no SKIP remain visible as LOW advisories; weak, missing or skipped verification remains REVIEW-worthy
- Pacman metadata-only drift is distinguished from content tampering, with sensitive executable and privileged paths remaining REVIEW-worthy
- expected browser sandbox SUID helpers require structural package/path context; a chrome-sandbox filename alone never bypasses review
- runtime network context now reports the actual peer endpoint from ss and collapses duplicate PID records for the same socket
- regression coverage includes the real false-positive patterns, a 42-scenario generic behavior/context/provenance corpus and dedicated runtime-network tests

The scanner remains evidence-weighted rather than whitelist-driven: benign wording is filtered by context, while real download/execute, encoded execution, credential exfiltration, persistence, privilege and confirmed IOC chains continue to escalate.

## Analysis modes

### Preflight

Statically inspect an AUR package before installation by package base name or canonical `aur.archlinux.org` URL:

```bash
aur-security-auditor preflight yay
aur-security-auditor preflight https://aur.archlinux.org/packages/yay --history
aur-security-auditor preflight yay --json --output yay-preflight.json
```

Preflight validates and parses the AUR snapshot as untrusted data. It does not source the PKGBUILD, execute included scripts or call `makepkg` for analysis.

It evaluates PKGBUILD and package metadata, install scripts, included source text, checksum quality, source provenance, runtime download chains, privilege escalation, persistence targets, destructive commands, mutable VCS references and optionally recent AUR Git history.

CLI exit codes:

- `0`: minimal or low risk
- `1`: moderate risk
- `2`: high or critical risk
- `3`: incomplete or failed analysis

### Local package-source inspection

The same static Preflight engine can analyze package sources before they are pushed to the AUR:

```bash
aur-security-auditor inspect ./PKGBUILD
aur-security-auditor inspect ./my-package-directory
aur-security-auditor inspect ./my-package-snapshot.tar.gz --json
```

Accepted local inputs are:

- a package directory containing `PKGBUILD`
- a direct path to `PKGBUILD`
- a supported package-source archive such as `.tar.gz`, `.tgz`, `.tar.xz`, `.tar.zst`, `.tar.bz2` or `.tar`
- a single text file only when it can be treated as package source and a PKGBUILD is present in the resulting input set

Local directories skip `.git`, `pkg` and `src` build trees. Archives are parsed in memory and are never extracted to the host filesystem. Absolute paths, traversal entries, special files, excessive member counts and size-limit violations are rejected.

### Update Guard

Update Guard stores an explicit review baseline for one exact package source and later reports only relevant differences.

In the dashboard, run Preflight and choose **Mark version as reviewed** / **Version als geprüft markieren**. The stored review is bound to:

- package base name and detected version
- complete snapshot/document-set SHA-256
- SHA-256 of each analyzed document
- declared sources and source hosts
- checksum algorithms and `SKIP` count
- PKGBUILD functions and install scripts
- privileged and sensitive package surfaces
- maintainer metadata when available
- normalized finding fingerprints

A review is not permanent trust. Any changed snapshot is compared again. Update Guard highlights:

- source and source-host additions or removals
- checksum-method removal or downgrade
- newly introduced `SKIP` checksums
- new build functions or install scripts
- new systemd, Pacman-hook, sudoers, Polkit, PAM or kernel-module surfaces
- maintainer changes
- new, unchanged and resolved security findings
- changed documents and the changed-document percentage

CLI workflows:

```bash
aur-security-auditor update-check yay
aur-security-auditor update-check ./my-package-directory --json
aur-security-auditor approve yay
aur-security-auditor approvals
aur-security-auditor approval-remove yay
```

Reviewed versions are stored locally in:

```text
~/.config/aur-security-auditor/update-guard.json
```

Removing a review does not uninstall a package and does not delete scan reports.

### Isolated deep scan

Build and inspect an AUR package without installing the generated package on the host:

```bash
sudo aur-security-auditor deep yay
sudo aur-security-auditor deep yay --json --output yay-deep-report.json
sudo aur-security-auditor deep yay --evidence yay-deep-evidence.zip
```

The deep scan performs Preflight first, extracts the validated snapshot into a temporary workspace, delegates the build to Arch `devtools` in a clean chroot and then inspects the resulting package archives. Safe repository-internal Git symlinks and hard links are preserved; absolute, escaping, dangling or path-parent links remain blocked.

It reports:

- clean-chroot build result and build duration
- generated package artifacts and complete archive inventory
- SUID and SGID files
- world-writable executable files
- package install scripts
- systemd, Pacman hook, sudoers, Polkit, PAM, kernel-module and other privileged surfaces
- Namcap output when available
- correlated risk findings with evidence

The generated package is not passed to Pacman and is not installed on the host. Saved deep-scan results, including failed attempts, can be removed from the dashboard without deleting packages or other scan data.

Install the optional tools used by this mode:

```bash
sudo pacman -S --needed devtools namcap libarchive
```

### Installed-system scan

The full system scan evaluates installed foreign and AUR packages, including:

- known campaign indicators and exact malicious hashes
- suspicious download, execution, obfuscation, exfiltration and persistence chains
- Pacman file-integrity deviations
- executable strings and native ELF hardening
- Linux file capabilities
- privileged system surfaces
- current AUR provenance and optional Git history
- differences from the previous completed scan

## Results and evidence

The dashboard separates:

- **Risk**: possible impact of the strongest correlated evidence
- **Confidence**: specificity and strength of that evidence
- **Coverage**: analysis modules that actually completed

Standard scan evidence contains:

```text
report.json
README.txt
manifest.sha256
```

Deep-scan evidence contains:

```text
deep-report.json
build.log
namcap.txt
manifest.sha256
```

The SHA-256 manifest verifies the bundle contents. It is an integrity manifest, not a digital signature.

## Dashboard

The interface includes:

- AUR and local package-source Preflight from one package field
- Update Guard with reviewed-version baseline and semantic security diff
- optional isolated deep scan for AUR packages
- full installed-system scan
- package inventory and detailed evidence
- scan-over-scan change tracking
- useful risk-distribution and coverage visualizations
- complete rolling ten-minute activity history that follows new entries only while the reader is already at the bottom
- maintained Help & About documentation with project background and maintainer links
- JSON export from every security-detail view
- complete English and German interface switching without a page reload

No scan starts automatically.

## Runtime tools

Required:

- Python 3
- Pacman

Used when available:

- `strings`
- `readelf` from `binutils`
- `getcap` from `libcap`
- `ss`
- `git`
- `vercmp`
- `devtools` for isolated clean-chroot builds
- `namcap` for PKGBUILD and package-quality checks
- `bsdtar` from `libarchive` for package inventory
- `zstd` for bounded local `.tar.zst` Preflight input

Missing optional tools are reported as reduced coverage. Missing deep-scan build prerequisites prevent only the isolated build mode.

## Upgrade and migration

The installer replaces previous standalone versions and migrates data from both historical identities, `aur-scanner` and `aur-malware-scanner`, into:

```text
~/.config/aur-security-auditor
~/.cache/aur-security-auditor
~/.local/state/aur-security-auditor
```

Reports, configuration, baselines, Update Guard reviews and exact-finding suppressions are preserved.

## Security boundaries

- dashboard listens only on loopback
- random free port by default
- strict loopback `Host` validation against DNS rebinding
- per-process CSRF token and same-origin POST validation
- restrictive Content Security Policy, COOP, CORP and Permissions Policy
- no external dashboard assets
- no `shell=True`
- bounded network downloads and archive parsing
- HTTPS-only AUR snapshot redirects
- archive traversal and special-file protection
- local source archives are parsed in memory and never extracted for Preflight
- PKGBUILD and included package scripts are never executed during static analysis
- isolated no-checkout Git inspection with hooks and unsafe transports disabled
- temporary deep-build workspace with validated snapshot extraction
- generated packages are inspected but never installed automatically
- review baselines, reports and suppressions remain on the system
- scanner state, reviews, reports, audit logs and evidence files use private user-only permissions
- private scanner data directories may not be symlinks

A clean result does not prove that a package or system is free of malware. Findings are intended for evidence-based triage and manual review.

## Tests

Built-in self-test:

```bash
aur-security-auditor --self-test
```

Complete source-tree regression suite:

```bash
./tests/run-tests.sh
```

## Uninstallation

Keep user data:

```bash
sudo ./uninstall.sh
```

Remove application and user data:

```bash
sudo ./uninstall.sh --purge
```
