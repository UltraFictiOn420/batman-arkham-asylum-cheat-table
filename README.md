# Batman Arkham Asylum GOTY - Cheat Engine project

Latest retained table; partial gameplay verification. Archive prepared 2026-10-07 from surviving project artifacts and conversation test reports.

Start with [the recommended table](tables/recommended/v7/Batman Arkham Asylum GOTY - Original v7.CT). Review the testing notes before enabling scripts.

## Navigation

| What you want | Where to look |
| --- | --- |
| Recommended versus historical versions | [Version catalog](catalog/VERSIONS.md) |
| Features by version, category, purpose, and code type | [Filterable CSV](catalog/features.csv) / [JSON](catalog/features.json) |
| Confirmed tests, incomplete features, and known bugs | [Project status](docs/STATUS_AND_TESTING.md) |
| What changed and why | [Development history](docs/HISTORY.md) |
| How to load and test safely | [Safety and setup](docs/SAFETY_AND_SETUP.md) |
| Source attribution and exclusions | [Provenance](docs/PROVENANCE.md) |
| Integrity checks | [SHA-256 manifest](CHECKSUMS.sha256) |

## Organization

- tables/recommended: selected baseline, not a promise that every feature is verified.
- tables/history: superseded original files retained for comparison.
- tables/experiments: incomplete or abandoned changes, clearly labeled.
- development/work: available original research and source files. Extensions identify Python (.py), PowerShell (.ps1), and Lua (.lua); table-embedded code is classified in the feature catalog.
- docs: project-specific decisions, gameplay evidence, known limitations, and safety guidance.
- catalog: machine-readable and human-readable indexes; these let you sort/filter without renaming source artifacts.

The catalogs are inventories, not automatic gameplay validation. See the status document for actual evidence. Original .CT files are copied byte-for-byte; development sources are retained where available. No game binaries, private dumps, dependency packages, or third-party reference tables are included.

Suggested GitHub issue labels: status:confirmed, status:partial, status:untested, status:abandoned, type:bug, type:feature, area:combat, area:survival, area:gadgets, area:teleport, area:timers, code:lua, code:auto-assembler, code:python, code:powershell. These are suggestions, not labels already created on GitHub.