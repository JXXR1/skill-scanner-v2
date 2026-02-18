# Skill Scanner v2

**Enhanced security scanner for OpenClaw/AgentPress skills**

Detects malicious patterns, supply chain attacks, and behavioral threats in AI agent skills before installation.

---

## 🚨 Why This Exists

AI agent skills can execute arbitrary code with your permissions. A malicious skill can:
- Steal your files (SOUL.md, MEMORY.md, credentials)
- Mine cryptocurrency using your CPU
- Establish reverse shells for remote access
- Inject persistence mechanisms
- Exfiltrate data via covert channels

**This scanner detects these threats before you install.**

---

## ✨ Features

### 20 Detection Categories

1. **Shell Injection** - Command execution patterns
2. **Crypto Miners** - XMRig, Stratum pools, mining algorithms
3. **Reverse Shells** - Remote access backdoors
4. **Fileless Malware** - Memory-resident threats
5. **Suspicious URLs** - Pastebin, code snippet sites
6. **Obfuscation** - Base64, hex encoding
7. **Code Complexity** - Minification, single-char variables
8. **Hardcoded Secrets** - Exposed API keys, passwords
9. **Time Bombs** - Delayed execution for evasion
10. **Persistence** - Crontabs, systemd, autostart
11. **Privilege Escalation** - sudo, setuid, pkexec exploits
12. **Covert Exfiltration** - DNS tunneling, Telegram bots, webhooks
13. **Network Patterns** - HTTP POST, fetch(), urllib
14. **Typosquatting** - Misspelled dependencies (reqests, expresss)
15. **Binary Files** - .exe, .dll, .so with SHA256 hashing
16. **Git History** - Force pushes, suspicious commit patterns
17. **Prerequisite Traps** - Manual install requirements
18. **Sandbox Testing** - Dynamic execution in firejail
19. **YARA Signatures** - 10 malware signatures
20. **Clawdex Verdict** - Community security database

---

## 📊 Exit Codes

- **0** = Clean (no issues found)
- **1-9** = Suspicious (review before installing)
- **10+** = Malicious (DO NOT INSTALL)

---

## 🚀 Quick Start

### Installation

```bash
git clone https://github.com/YOUR_ORG/skill-scanner-v2
cd skill-scanner-v2
sudo bash install.sh
```

### Usage

```bash
# Scan a skill directory
skill-scan-v2.sh /path/to/skill

# Scan by skill name (searches /opt/clawdbot/skills/)
skill-scan-v2.sh weather

# Check exit code
skill-scan-v2.sh suspicious-skill && echo "SAFE" || echo "THREAT DETECTED"
```

---

## 🧪 Certification

This scanner has been **certified** with a comprehensive test suite:

```bash
cd test-suite
bash run-certification.sh
```

**Test Coverage:**
- ✅ Crypto miner detection (xmrig + stratum pool)
- ✅ Reverse shell detection (bash -i >& /dev/tcp/)
- ✅ Infostealer detection (workspace files + pastebin)
- ✅ Typosquatting detection ("reqests", "expresss")
- ✅ Obfuscation detection (base64, atob, setTimeout)
- ✅ Clean code validation (no false positives)

**Result: 100% detection accuracy (7/7 tests passed)**

---

## 📖 Examples

### Example 1: Clean Skill

```bash
$ skill-scan-v2.sh weather-skill

🔍 Scanning: weather-skill (Enhanced v2)
   Path: /opt/clawdbot/skills/weather-skill

=== Shell Injection Patterns ===
✅ No shell injection patterns

=== Cryptocurrency Mining Patterns ===
✅ No crypto mining patterns

[... 18 more checks ...]

===========================================
✅ SCAN COMPLETE: No issues found
```

**Exit code: 0** → Safe to install

---

### Example 2: Malicious Skill (Crypto Miner)

```bash
$ skill-scan-v2.sh crypto-miner

🔍 Scanning: crypto-miner (Enhanced v2)
   Path: ./crypto-miner

=== Cryptocurrency Mining Patterns ===
crypto-miner/skill.py:xmrig --donate-level=1 -o stratum+tcp://pool.minexmr.com:4444
🚫 CRYPTO MINER DETECTED

=== YARA Signature Scan ===
🚫 MALWARE SIGNATURE MATCH:
CryptoMiner_Generic crypto-miner/skill.py

===========================================
🚫 SCAN COMPLETE: MALICIOUS - DO NOT INSTALL
   Total issues: 20
```

**Exit code: 20** → Malicious, blocked

---

### Example 3: Suspicious Skill (Needs Review)

```bash
$ skill-scan-v2.sh obfuscated-skill

🔍 Scanning: obfuscated-skill (Enhanced v2)
   Path: ./obfuscated-skill

=== Obfuscation Patterns ===
obfuscated-skill/index.js:eval(Buffer.from("Y29uc29sZS5sb2c...", "base64"))
⚠️  Found potential obfuscation (base64/hex encoding)

=== Time Bomb Detection ===
obfuscated-skill/index.js:setTimeout(() => { exec(cmd); }, 5000);
⚠️  Found delayed execution (possible evasion)

===========================================
⚠️  SCAN COMPLETE: 4 potential issue(s) - review before installing
```

**Exit code: 4** → Suspicious, manual review required

---

## 🔧 Configuration

### Environment Variables

```bash
# Custom YARA rules location
export YARA_RULES="/path/to/custom-rules.yar"

# Custom Clawdex API endpoint
export CLAWDEX_API="https://custom.clawdex.api/skill"
```

### YARA Rules

YARA signatures are located in `/var/lib/yara/rules/openclaw-malware.yar`

**10 signatures included:**
1. `OpenClaw_Infostealer` - Workspace file exfiltration
2. `CryptoMiner_Generic` - Cryptocurrency miners
3. `ReverseShell_Generic` - Backdoor shells
4. `Obfuscated_PowerShell` - Encoded PowerShell
5. `SSH_Backdoor` - Unauthorized key injection
6. `Fileless_Malware` - Memory-resident threats
7. `Persistence_Mechanism` - Crontabs, systemd
8. `WebShell_PHP` - PHP webshells
9. `Typosquatting_NPM` - Misspelled packages
10. `PrivEsc_Exploit` - Privilege escalation

---

## 🛡️ Best Practices

### Before Installing Any Skill

1. **Always scan first:**
   ```bash
   skill-scan-v2.sh ./new-skill && openclaw install ./new-skill
   ```

2. **Review suspicious findings manually:**
   - Check why patterns were flagged
   - Validate legitimate use cases (e.g., a legit mining monitoring tool)

3. **Trust certified sources:**
   - Official OpenClaw skills: Usually safe
   - Community skills: Scan first
   - Unknown GitHub repos: **Mandatory scan**

### When Writing Skills

1. **Avoid patterns that trigger false positives:**
   - Don't use `eval()` or `exec()` unless necessary
   - Don't hardcode credentials (use environment variables)
   - Document any suspicious-looking code in comments

2. **Test your skill:**
   ```bash
   skill-scan-v2.sh ./my-new-skill
   ```

3. **Submit to Clawdex for community vetting**

---

## 🤝 Integration

### Pre-commit Hook

```bash
#!/bin/bash
# .git/hooks/pre-commit
skill-scan-v2.sh . || {
  echo "❌ Security scan failed - commit blocked"
  exit 1
}
```

### CI/CD Pipeline (GitHub Actions)

```yaml
name: Security Scan

on: [push, pull_request]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      - name: Install Scanner
        run: |
          git clone https://github.com/YOUR_ORG/skill-scanner-v2
          cd skill-scanner-v2 && sudo bash install.sh
      - name: Scan Skill
        run: skill-scan-v2.sh .
```

### Automated Daily Audits

```bash
# /etc/cron.daily/skill-audit
#!/bin/bash
for skill in /opt/clawdbot/skills/*; do
  skill-scan-v2.sh "$skill" || echo "⚠️  $skill flagged"
done
```

---

## 📦 Dependencies

**Required:**
- `bash` 4.0+
- `grep`, `find`, `awk`, `sed` (GNU coreutils)
- `jq` (JSON parsing)
- `curl` (Clawdex API)

**Optional (but recommended):**
- `yara` (signature scanning)
- `firejail` (sandbox testing)
- `git` (repository analysis)

---

## 🐛 Troubleshooting

### YARA not found

```bash
sudo apt install yara  # Debian/Ubuntu
sudo yum install yara  # RHEL/CentOS
brew install yara      # macOS
```

### Firejail not available

Sandbox tests will be skipped. Install:
```bash
sudo apt install firejail
```

### False positives

If a legitimate skill triggers warnings:
1. Review the flagged code manually
2. Check if patterns are actually malicious
3. Add exceptions to your local fork if needed

---

## 📝 License

MIT License - See [LICENSE](LICENSE) for details

---

## 🙏 Credits

**Author:** EVE (OpenClaw Security)  
**Inspired by:** Real-world infostealer threats targeting AI agents  
**Community:** OpenClaw Discord, ClawHub contributors

---

## 🔗 Links

- **GitHub:** https://github.com/YOUR_ORG/skill-scanner-v2
- **Clawdex:** https://clawdex.koi.security
- **OpenClaw Docs:** https://docs.openclaw.ai
- **Report Issues:** https://github.com/YOUR_ORG/skill-scanner-v2/issues

---

## 🚀 Roadmap

- [ ] Machine learning-based anomaly detection
- [ ] Integration with OpenClaw CLI (`openclaw scan`)
- [ ] Real-time monitoring daemon
- [ ] Docker image for isolated scanning
- [ ] Web UI for scan reports
- [ ] ClamAV integration
- [ ] Automatic YARA rule updates from threat feeds

---

**Stay safe. Scan before you install.** 🛡️
