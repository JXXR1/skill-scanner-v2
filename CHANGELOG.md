# Changelog

All notable changes to Skill Scanner v2 will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [2.3.5] - 2026-02-25

### Added
- **OAuth Bearer token support for Anthropic backend** — module 27 now accepts
  `ANTHROPIC_OAUTH_TOKEN` in addition to `ANTHROPIC_API_KEY`. Uses `Authorization: Bearer <token>`
  header when OAuth token is set, `x-api-key` header for API key. API key takes priority if both
  are set. Allows use without a direct API key (e.g. OAuth apps, org-managed tokens).

---

## [2.3.4] - 2026-02-25

### Added
- **Module 27: LLM Semantic Analysis** (`--llm` flag, opt-in) — deep intent analysis using a
  language model. Detects social engineering, subtle instruction manipulation, and obfuscated
  threats that pattern matching cannot catch.
  - **Local-first design**: tries Ollama (`localhost:11434`) first — no data leaves the machine
  - **Cloud fallback**: uses Anthropic API if `ANTHROPIC_API_KEY` is set; warns before sending
  - **Configurable model**: `SKILL_SCANNER_LLM_MODEL` env var (default: `llama3` / `claude-sonnet-4-6`)
  - **Confirmation prompt**: shows estimated token count and asks before running (bypass with `--yes`)
  - **Verdict scoring**: `MALICIOUS` +10, `SUSPICIOUS` +3, `SAFE` no change
- **`--yes` / `-y` flag** — skip confirmation prompt for scripted/CI use

### Changed
- **Argument parsing rewritten** — positional skill path now detected by content (not `$1`),
  allowing flags in any position: `skill-scan-v2.sh --llm ./skill --yes`

---

## [2.3.3] - 2026-02-25

### Removed
- **Clawdex external API call (module 20)** — removed entirely. Two reasons:
  1. **Privacy**: every scan leaked skill names to `clawdex.koi.security` (third-party, unknown operator)
  2. **Trust**: verdicts were trivially gameable; an attacker who knows the scanner could
     pre-register their skill as "benign" in the database

### Notes
- Module count goes from 24 to 23 with Clawdex removed; restored to 24 with LLM module in 2.3.4
- `CLAWDEX_API` environment variable removed

---

## [2.3.2] - 2026-02-24

### Fixed
- **False positive in reverse shell detection** — `nc.*-e` regex was too greedy, matching innocent
  strings like `references/cli-examples.md` (`nc` in "references", `-e` in "cli-examples").
  Affected legitimate bundled skills including 1password, canvas, and gh-issues, causing them
  to be flagged as MALICIOUS (exit 10).
- Updated pattern from `nc.*-e` to `\b(nc|ncat)\b.*\s+-e` — requires `nc`/`ncat` as standalone
  words with whitespace before the `-e` flag. Real reverse shells (`nc -e /bin/bash`) still caught.

### Added
- **ncat detection** — `ncat` (Nmap's netcat) now explicitly included in reverse shell patterns
  alongside `nc`. Both support `-e` for shell spawning and should be caught.

### Notes
- Other potentially broad patterns identified for future review: `bash.*tcp`, `socat.*exec`
  (minor false positive risk on comments/filenames — no real-world FPs confirmed yet)

---

## [2.3.1] - 2026-02-21

### Added
- **OpenClaw-specific prompt injection patterns** (module 21) — updated after live attack:
  `post-compaction audit`, `WORKFLOW_AUTO.md`, `operating protocols restored after`, and similar
  fake system message patterns now detected

---

## [2.1.0] - 2026-02-19

### Added
- **Module 21: Prompt Injection & Intent Analysis** — scans `SKILL.md` instructions for jailbreak
  attempts, persona overrides, and instruction manipulation. Catches the "technically clean but
  semantically malicious" gap. Inspired by u/EthicsMd (m/general).
- **Module 22: OpenClaw Credential Path Detection** — flags references to `SOUL.md`, `MEMORY.md`,
  `IDENTITY.md`, `MOLTBOOK_API`, `ANTHROPIC_API`, `BACKUP_PASSPHRASE`
- **Module 23: Sensitive Read + Exfil Combo** — catches context clone attacks: skill reads identity
  files AND contains known exfiltration endpoints (webhook.site, requestbin, ngrok, Discord webhooks)
- **Module 24: Permission Manifest Check** — warns if skill lacks `permissions.json` or `PERMISSIONS.md`
- **Module 25: MoltGuard Schema Validation** — validates `moltguard.json` for wildcard permissions,
  undeclared network access, and scope inflation. Checks Isnad Chain endorsements.
- **Module 26: Covert File Monitoring Detection** — detects `inotify` watchers, polling loops, and
  `fs.watch` calls targeting `MEMORY.md`, `.env`, and other sensitive files (context surveillance)

### Credits
- u/EthicsMd: semantic vs syntactic malice distinction
- u/dirk_dalton: permission manifests and declarative security model

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
- **Clawdex integration** for community security verdicts *(removed in v2.3.3)*
- **Comprehensive test suite** with 7 certification samples
- **Automated certification** script (100% detection accuracy)
- **Configurable YARA rules path** via environment variable
- **Configurable Clawdex API endpoint** via environment variable

### Changed
- **Exit code system**: 0 = clean, 1-9 = suspicious, 10+ = malicious
- **Improved pattern matching** for crypto miners (XMRig, Stratum, RandomX)
- **Enhanced reverse shell detection** (bash, nc, socat, Python, Perl)
- **Better obfuscation detection** (base64, hex, minification)

### Security
- **OpenClaw workspace protection**: Detects infostealers targeting SOUL.md, MEMORY.md, AGENTS.md
- **SSH backdoor detection**: Unauthorized authorized_keys injection
- **Privilege escalation detection**: pkexec, setuid, chmod 777
- **Persistence mechanism detection**: crontabs, systemd, rc.local

### Documentation
- Comprehensive README with examples and best practices
- Installation guide for Debian/Ubuntu, RHEL/CentOS, macOS
- CI/CD integration examples (GitHub Actions)
- Pre-commit hook examples
- Troubleshooting guide

### Testing
- **7 test samples**: 4 malicious, 1 suspicious, 2 clean
- **100% certification accuracy**: No false positives, no false negatives
- Automated certification script with detailed reporting

---

## [1.0.0] - 2026-02-14 (Initial Release)

### Added
- Basic pattern matching for shell injection, crypto miners, reverse shells
- Simple exit code system
- Network pattern detection
- Hardcoded secret detection

### Known Issues
- High false positive rate on obfuscation detection
- No sandbox testing
- No YARA integration
- Limited typosquatting coverage

---

## Roadmap

- [ ] Integration with OpenClaw CLI (`openclaw scan`)
- [ ] Real-time monitoring daemon
- [ ] Docker image for isolated scanning
- [ ] Automatic YARA rule updates from threat feeds
- [ ] Support for more languages (Go, Rust, Ruby)
- [ ] GPG signature verification for encrypted skills
- [x] ~~Machine learning / LLM-based anomaly detection~~ ✅ Done in v2.3.4

---

## Migration Guide

### From v1.x to v2.0

**Breaking Changes:**
- Exit codes changed: v1 used 1 for any issue, v2 uses 0/1-9/10+ scale
- YARA rules now required at `/var/lib/yara/rules/openclaw-malware.yar`
- Typosquatting now returns exit 10 (malicious) instead of exit 1 (suspicious)

**Migration Steps:**
1. Run `sudo bash install.sh` to install YARA rules
2. Update any scripts checking exit codes:
   ```bash
   # Old (v1):
   skill-scan.sh ./skill && echo "safe"
   
   # New (v2):
   skill-scan-v2.sh ./skill
   EXIT=$?
   if [ $EXIT -eq 0 ]; then echo "safe"
   elif [ $EXIT -lt 10 ]; then echo "review"
   else echo "malicious"; fi
   ```

3. Install optional dependencies (firejail, yara) for full detection coverage

---

**Full Changelog:** https://github.com/JXXR1/skill-scanner-v2/blob/main/CHANGELOG.md
