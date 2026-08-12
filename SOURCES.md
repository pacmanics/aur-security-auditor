# Sources

Retrieved 2026-08-05.

## Threat intelligence

- Arch Linux: Active AUR malicious packages incident
  - https://archlinux.org/news/active-aur-malicious-packages-incident/
- Sonatype Research: Atomic Arch campaign analysis
  - https://www.sonatype.com/blog/atomic-arch-npm-campaign-adds-malicious-dependency
- Community campaign data and IOC consolidation
  - https://github.com/lenucksi/aur-malware-check

The bundled package-name list is an exposure list, not proof that the currently installed version is malicious. The scanner only raises a confirmed-threat verdict from exact artifacts or IOCs; package-list matches are review context and are correlated with the local installation or update window.

## Arch build and package-analysis tooling

- `pkgctl build`
  - https://man.archlinux.org/man/pkgctl-build.1.en
- `archbuild` and repository-specific clean-chroot helpers such as `extra-x86_64-build`
  - https://man.archlinux.org/man/extra/devtools/archbuild.1.en
- `makechrootpkg`
  - https://man.archlinux.org/man/makechrootpkg.1
- Namcap
  - https://wiki.archlinux.org/title/Namcap

## AUR security model and project background

- ArchWiki: Arch User Repository
  - https://wiki.archlinux.org/title/Arch_User_Repository
- ArchWiki: AUR helpers and package-file review
  - https://wiki.archlinux.org/title/AUR_helpers
- AUR package search for maintainer `pacmanics`
  - https://aur.archlinux.org/packages?K=pacmanics&SeB=m
- Project maintainer website
  - https://altbox.de/
