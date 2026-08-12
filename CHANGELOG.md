# Changelog

## 1.4.7

- Added a dedicated desktop launcher that explains why privileged access is required before sudo authentication is requested.
- Added a restrained English terminal startup sequence and security banner for application-menu launches, with a no-animation fallback for non-interactive sessions.
- Desktop launches now use `/usr/bin/aur-security-auditor-launcher`; terminal and CLI output stay English, while German is available only through the browser dashboard language switch.
- Replaced the previous personal maintainer identity and AUR handle throughout the UI, documentation and source references with `pacmanics`.
- Changed visible copyright branding to `© PacmanicS`.
- Updated the Help & About AUR package link to the `pacmanics` maintainer search.
- Added final AUR packaging metadata for `aur-security-auditor`.
- Removed malformed placeholder entries such as `http://[IP` and `https://[IP` from source provenance, including previously saved reports displayed by the dashboard.
- Fixed full-scan cancellation sending an empty POST without the required JSON content type.
- Added context-aware finding evaluation that separates executable behavior from documentation, wordlists, CI files, tests, fixtures, assets and foreign-platform binaries.
- Removed package verdict impact from non-executable examples such as README commands, metadata instructions and scanner wordlists.
- Tightened network and process-hiding heuristics to remove broad token matches from minified assets and ordinary runtime libraries.
- Correlates persistence, credential, network and privilege signals only within the same actionable file context.
- Explains package-managed SUID permission changes as an expected privileged surface when the install script applies the same mode.
- Added contextual signal counts to package exports while retaining raw signals for evidence.
- Replaced the dependency graph scroll area with an interactive pan, zoom and fit-to-view graph showing all loaded nodes.
- Improved package detail layout and dependency relationship legend.

## 1.4.4

- Added client-side package-detail caching and a five-minute backend dependency-graph cache to reduce repeated loading.
- Changed `Mark as legitimate` / `Als legitim markieren` to update the open package details immediately from the mutation response instead of closing into another loading cycle.
- Added JSON exports to package details, Preflight details, isolated deep-scan details and Update Guard comparisons.
- Changed the activity log from arbitrary entry limits to the complete rolling ten-minute event window while retaining manual scroll position.
- Expanded Help & About with a product introduction, the security rationale behind the auditor, the June 2026 malicious AUR package incident and maintained links to altbox.de, Arch Linux guidance and the maintainer's AUR package search.
- Restricted Source URLs to actual declared package sources. Expanded `.SRCINFO` values take precedence over unresolved PKGBUILD variables; URLs found only in comments, documentation, tests or local web examples are no longer presented as package sources.
- Kept genuinely declared localhost or direct-IP sources visible so they can still be rated as security evidence instead of being silently hidden.
- Added regression coverage for detail caching, immediate suppression updates, rolling log retention, source provenance cleanup, exports and the expanded About view.

## 1.4.2

- Fixed isolated deep scans rejecting legitimate in-tree Git symlinks contained in AUR snapshots.
- Added strict lexical validation for symbolic links and hard links: targets must exist inside the same package root and may never escape the temporary workspace.
- Continued to reject absolute links, traversal links, dangling links, devices, FIFOs, unsupported archive entries and links used as parent paths.
- Added stable deep-scan error codes so saved failures are re-rendered correctly when switching between English and German.
- Added a neutral `Remove` / `Entfernen` action for successful and failed deep-scan results.
- Added `/api/deep/clear` and safe deletion of the persisted deep report without touching packages, standard reports or Preflight results.
- Expanded deep-scan regression coverage for safe symlinks, escaping links, special archive entries, localized failures and result removal.

## 1.4.1

- Hardened the loopback dashboard against DNS-rebinding and forged `Host` requests.
- Added same-origin validation for browser POST requests and stricter JSON request validation.
- Added COOP, CORP, Permissions Policy and stronger CSP directives to dashboard responses.
- Changed reports, Update Guard reviews, suppressions, audit logs and Evidence ZIP files to private user-only permissions.
- Rejected symlinked private data directories and stopped the privileged installer from following user-controlled scanner data symlinks.
- Made JSON and evidence persistence crash-safe with atomic writes, file synchronization and directory synchronization.
- Added the documented `deep --evidence` CLI option, including evidence output for failed clean-chroot builds when a partial report exists.
- Hardened CLI report output and standalone scanner report files against partial writes and symlink targets.
- Added port-range validation and made delayed browser startup non-blocking during shutdown.
- Removed a duplicate self-test failure entry and expanded security regression coverage.

## 1.4.0

- Added Update Guard for version-bound review baselines of AUR and local package sources.
- Added semantic security diffs that highlight source, host, checksum, `SKIP`, build-function, install-script, privileged-surface, maintainer and finding changes.
- Added exact-match detection based on the analyzed package version, snapshot digest and per-document SHA-256 hashes.
- Added dashboard actions to mark the current package source as reviewed, inspect later changes and remove a stored review.
- Added a visual changed-document ring and concise Update Guard summary without adding another general-purpose dashboard section.
- Added static analysis of local package directories, individual `PKGBUILD` paths and supported source archives.
- Local archives are parsed in memory with path-traversal, special-file, member-count, per-file and aggregate-size protection; package code is never executed.
- Added `inspect`, `update-check`, `approve`, `approvals` and `approval-remove` CLI workflows.
- Added Update Guard API endpoints and persisted review data under the invoking user's configuration directory.
- Expanded Help, package input guidance and English/German translations for the complete Update Guard workflow.
- Added regression coverage for exact reviews, semantic change classification, local directory/archive analysis, unsafe archive rejection and review removal.

## 1.3.1

- Completed a full English/German interface audit across the dashboard, Help, scan options, Preflight, deep analysis, package details, dialogs, live states, tooltips and accessibility labels.
- Reworked Help & About to use the maintained translation dictionary and to update immediately when the language changes.
- Added a neutral `Remove` / `Entfernen` action for deleting only the saved Preflight dashboard result.
- Added a dedicated backend endpoint for safely clearing the persisted Preflight report while leaving packages and system reports untouched.
- Fixed scan-option layout so descriptions always appear below their bold titles with stable spacing and wrapping.
- Fixed remaining untranslated or mixed-language labels, including initial package progress, deep-build phases, artifact metadata, security-surface names and status details.
- Fixed navigation alignment with a stable two-column grid and preserved responsive behavior.
- Added an automated bilingual interface audit and removal-endpoint regression test.

## 1.3.0

- Added isolated deep analysis for AUR packages using an Arch clean-chroot build.
- Added `aur-security-auditor deep` with JSON report and Evidence ZIP output.
- Added dashboard controls and live status for deep builds.
- Added generated package-archive inventory without installing the package on the host.
- Added detection of SUID, SGID and world-writable executable files in built artifacts.
- Added inventory and correlation for privileged package surfaces such as systemd units, Pacman hooks, sudoers, Polkit, PAM and kernel modules.
- Added optional Namcap execution and preserved its full output in the evidence bundle.
- Added deep Evidence ZIP exports containing the report, build log, Namcap output and SHA-256 manifest.
- Added a maintained bilingual Help & About view.
- Added risk-distribution donut visualization, deep-scan coverage ring and restrained interface transitions.
- Replaced visible diagnostic badges with the final application footer: `AUR Security Auditor`, `© PacmanicS`, `v1.3.0`.
- Fixed navigation-label alignment with a stable grid layout.
- Fixed activity-log column overlap and long-message wrapping.
- Simplified dashboard startup output by removing the redundant bind-status line.

## 1.2.0

- Added static pre-install AUR package analysis by package name or canonical AUR URL.
- Added dashboard Preflight panel with separate risk, confidence and coverage.
- Added `aur-security-auditor preflight` CLI with JSON output and automation-friendly exit codes.
- AUR snapshots are parsed in memory with strict path, member and size limits. PKGBUILD and included scripts are never sourced or executed.
- Added checks for runtime downloads, privilege escalation, destructive commands, dynamic shell sourcing, checksum quality, mutable VCS sources and sensitive system targets.
- Added optional bounded AUR Git history analysis to Preflight with no checkout, disabled hooks, isolated Git configuration and blocked local/external transports.
- Added HTTPS redirect validation and independent source collection from both `.SRCINFO` and `PKGBUILD`.
- Added positive security signals and an explicit non-guarantee recommendation.
- Fixed the missing `tempfile` import used by optional AUR Git history analysis.

## 1.1.0

- Added native ELF hardening analysis for executable stacks, W+X segments, unsafe interpreters and unsafe library search paths.
- Added Linux file-capability inspection and conservative entropy correlation.
- Added privileged security-surface inventory for sudoers, Polkit, PAM, kernel modules, systemd, Pacman hooks, udev, cron and autostart artifacts.
- Added current AUR source provenance with source hosts, checksums, skipped checksums and snapshot SHA-256.
- Added installed-versus-AUR version comparison and expanded AUR package metadata.
- Added optional bounded recent AUR Git history analysis.
- Added baseline comparison with new, resolved, version and verdict changes.
- Added Evidence ZIP export with SHA-256 manifest.
- Added report schema version 2 and explicit capability metadata.
- Expanded package details and dashboard change reporting.
- Added dedicated security-feature and two-scan integration regression tests.

## 1.0.2

- Fixed Python `DeprecationWarning` in dependency parsing by passing `maxsplit` as a keyword argument.

## 1.0.1

- Made the top navigation fixed while scrolling.
- Froze scan runtime after completion, cancellation or failure.
- Clarified the root-access indicator.
- Separated AUR and upstream links.
- Fixed activity-log following behavior.
- Added the application icon and favicon.

## 1.0.0

- First release under the final `aur-security-auditor` identity.
