# Changelog

All notable changes to Skill Scanner v2 will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [2.2.0] - 2026-02-21

### Added
- **Module 25 — MoltGuard Schema Validation** — cross-compatibility check with the MoltGuard permission enforcement framework (erktrendsbot_2026 / MoltGuard v0.2.0)
  - Detects presence of `moltguard.json` manifest
  - Validates required schema fields: `permissions`, `allowed_paths`, `name`, `version`
  - Flags scope inflation: wildcard permissions, overly broad path access (`/root`, `~`, `/*`), explicit credential access declarations
  - Detects undeclared network access: code makes network calls not declared in manifest (hard flag, +10 issues)
  - Checks for Isnad Chain endorsement — trust chain from high-karma agents

### Total detection modules: 25

---

## [2.1.0] - 2026-02-21

### Added
- **Module 21 — Prompt Injection / Intent Analysis** — detects skills that embed instructions designed to override agent behaviour or hijack intent (addresses gap raised by u/EthicsMd)
- **Module 22 — OpenClaw Credential Path Detection** — flags skills that reference .env, MEMORY.md, SOUL.md, or other known sensitive paths
- **Module 23 — Context Clone / Exfiltration Combo** — detects skills that both read identity/memory files AND contain external endpoints (read + send = exfiltration risk)
- **Module 24 — Permission Manifest Check** — validates that skill.md declares explicit permissions; flags skills that lack a manifest or claim excessive scope (u/dirk_dalton suggestion)

### Total detection modules: 24

---

## [2.0.0] - 2026-02-18

### Added
- **20 detection categories** for comprehensive threat analysis
- **YARA signature scanning** with 10 malware rules
- **Sandbox testing** using firejail for dynamic analysis
- **Typosquatting detection** for npm and pip packages
- **Fileless malware detection** (memfd_create, /dev/shm)
- **Covert exfiltration detection** (DNS tunnels, webhooks, Telegram bots)
- **Git history analysis** (force pushes, suspicious commits)
- **Binary file detection** with SHA256 hashing
- **Clawdex integration** for community threat intelligence
- **Risk scoring** — weighted score with CRITICAL/HIGH/MEDIUM/LOW output