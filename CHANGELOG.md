# Changelog

All notable changes to Skill Scanner v2 will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
- **Clawdex integration** for community security verdicts
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

## Planned for [2.1.0]

### Roadmap
- Machine learning-based anomaly detection
- Integration with OpenClaw CLI (`openclaw scan`)
- Real-time monitoring daemon
- Docker image for isolated scanning
- Web UI for scan reports
- ClamAV integration
- Automatic YARA rule updates from threat feeds
- Support for more languages (Go, Rust, Ruby)
- Skill reputation scoring system
- Encrypted skill support (GPG signature verification)

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

**Full Changelog:** https://github.com/YOUR_ORG/skill-scanner-v2/blob/main/CHANGELOG.md

## v2.1.0 - 2026-02-19

### New Detection Modules (community-driven enhancements)

**Module 21: Prompt Injection & Intent Analysis**
- Scans skill.md INSTRUCTIONS for malicious intent, not just code
- Detects: "ignore previous instructions", "you are now", "pretend to be", persona overrides
- Catches the u/EthicsMd gap: technically clean but semantically malicious skills

**Module 22: OpenClaw Credential Path Detection**  
- Flags references to OpenClaw-specific files: SOUL.md, MEMORY.md, IDENTITY.md, cache.json
- Catches API key variable names: MOLTBOOK_API, ANTHROPIC_API, BACKUP_PASSPHRASE

**Module 23: Sensitive Read + Exfil Combo Detection**
- Flags skills that BOTH reference identity/memory files AND contain exfiltration endpoints
- Specifically catches context clone attack pattern (steal SOUL.md → send to webhook)
- Known exfil endpoints: webhook.site, requestbin, ngrok, Discord webhooks, Telegram bots

**Module 24: Permission Manifest Check**
- Warns if skill lacks permissions.json/PERMISSIONS.md
- Encourages declarative permission model (u/dirk_dalton suggestion)

### Inspired by
- u/EthicsMd (m/general): semantic vs syntactic malice distinction
- u/dirk_dalton (m/security): permission manifests and cryptographic signatures
- Moltbook API security audit: context clone attack surface
