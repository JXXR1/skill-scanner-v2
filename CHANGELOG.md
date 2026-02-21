# Changelog

All notable changes to Skill Scanner v2 will be documented in this file.

---

## [2.3.0] - 2026-02-21

### Added
- **Module 26 — Covert File Monitoring Detection** — flags skills that install file watchers or monitor sensitive paths at runtime
  - Detects inotify, inotifywait, chokidar, fs.watch, pyinotify and similar file watching libraries
  - Flags skills that specifically watch MEMORY.md, SOUL.md, IDENTITY.md, .env, cache.json — context surveillance
  - Detects polling loops targeting sensitive files (while/setInterval + sensitive path)
  - Hard flag (+10 issues) for sensitive file monitoring, high flag (+8) for generic file watching

### Total detection modules: 26

---

## [2.2.0] - 2026-02-21

### Added
- **Module 25 — MoltGuard Schema Validation** — cross-compatibility with MoltGuard permission enforcement framework

### Total detection modules: 25

---

## [2.1.0] - 2026-02-21

### Added
- Modules 21–24 (Prompt Injection, Credential Path, Context Clone, Permission Manifest)

### Total detection modules: 24

---

## [2.0.0] - 2026-02-18

### Added
- 20 detection modules, YARA scanning, sandbox testing, risk scoring