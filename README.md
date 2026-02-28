# Skill Scanner v3

**Security scanner for OpenClaw/AgentPress skills — pattern matching, AST taint tracking, and LLM semantic analysis.**

Detects malicious patterns, data exfiltration chains, supply chain attacks, and behavioral threats in AI agent skills before installation.

> 💡 **Best used in conjunction with the [Cisco Skill Scanner](https://github.com/cisco-open/skill-scanner)** for maximum coverage. Run both before installing any skill.

---

## 🚨 Why This Exists

AI agent skills can execute arbitrary code with your permissions. A malicious skill can:
- Steal your files (SOUL.md, MEMORY.md, credentials)
- Mine cryptocurrency using your CPU
- Establish reverse shells for remote access
- Inject persistence mechanisms
- Exfiltrate data via covert channels
- **Inject instructions into your agent** (prompt injection)

**This scanner detects these threats before you install.**

---

## ✨ Features

### 28 Detection Modules

**Static Pattern Analysis (1–19)**
1. **Shell Injection** — Command execution patterns (`curl | sh`, `eval()`, backticks)
2. **Crypto Miners** — XMRig, Stratum pools, mining algorithms, RandomX
3. **Reverse Shells** — `bash -i`, `nc`/`ncat -e`, `/dev/tcp/`, socat, Python pty
4. **Fileless Malware** — `memfd_create`, `/dev/shm`, `/proc/self/exe`
5. **Suspicious URLs** — Pastebin, hastebin, rentry, ghostbin (common malware hosts)
6. **Obfuscation** — Base64, hex encoding, single-char variable density
7. **Code Complexity** — Minified files, high obfuscation indicators
8. **Hardcoded Secrets** — Passwords, API keys, tokens in source code
9. **Time Bombs** — Delayed execution, large `sleep()` / `setTimeout()` values
10. **Persistence** — Crontab, systemd, `.bashrc`, `rc.local`, autostart entries
11. **Privilege Escalation** — `sudo`, `pkexec`, `setuid`, `chmod 777`
12. **Data Exfiltration Channels** — DNS tunneling, ICMP, Telegram/Discord webhooks
13. **Network Patterns** — HTTP requests, fetch, axios (flagged for review)
14. **Dependency Typosquatting** — `reqests`, `beautfiulsoup`, `numbpy` in package manifests
15. **Binary Detection** — `.exe`, `.dll`, `.so` files with SHA256 hashing
16. **Git History** — Force pushes, commit spam (>10 in 1 hour)
17. **Prerequisite Traps** — README instructions designed to trick users into running malicious setup
18. **Sandbox Testing** — Runs `install.sh` in firejail (network + filesystem isolated)
19. **YARA Signatures** — Malware signature scanning with custom rulesets

**Intent & Behavioral Analysis (20–26)**
20. **Prompt Injection** — Jailbreaks, role overrides, hidden instructions in skill files
21. **Context Poisoning** — Memory file manipulation, SOUL.md/MEMORY.md targeting
22. **Credential Harvesting** — Patterns designed to extract auth tokens and API keys
23. **Social Engineering** — Instructions targeting human operators in README/docs
24. **Supply Chain** — Dependency confusion, typosquatting in install scripts
25. **MoltGuard Schema** — Validates against known malicious OpenClaw skill structures
26. **Covert File Monitoring** — `inotify`/`chokidar`/`fs.watch` targeting sensitive files

**Advanced Analysis (27–28)** *(new in v3.0.0)*
27. **AST Taint Tracking** — Traces data flow from user input to dangerous sinks (`eval`, `exec`, `subprocess`, `os.system`) across Python files
28. **Cross-Language Source→Sink Analysis** — Same taint tracking extended to JavaScript and Shell scripts

### LLM Semantic Analysis *(optional)*
Pass `--llm` to run an additional AI-powered semantic analysis layer that catches:
- Social engineering disguised as legitimate functionality
- Obfuscated intent that passes static analysis
- Prompt injection embedded in documentation or config files

Requires Ollama running locally or configure `OLLAMA_URL` env variable.

---

## 🚀 Usage

```bash
# Pattern scan (28 modules, free)
skill-scan-v2.sh ./my-skill

# Full scan with LLM semantic analysis
skill-scan-v2.sh ./my-skill --llm

# Scan an installed OpenClaw skill by name
skill-scan-v2.sh weather

# List all installed skills and scan each
skill-scan-v2.sh --list
```

---

## 🔗 Recommended: Use with Cisco Skill Scanner

For maximum coverage, run both scanners before installing any skill:

```bash
# Step 1: Our scanner (pattern + AST + LLM)
skill-scan-v2.sh ./my-skill --llm

# Step 2: Cisco Skill Scanner (complementary detection)
skill-scanner ./my-skill
```

The two scanners use different detection approaches and complement each other. Neither should be used alone.

---

## 📦 Installation

```bash
curl -fsSL https://raw.githubusercontent.com/JXXR1/skill-scanner-v2/main/skill-scan-v2.sh \
  -o /usr/local/bin/skill-scan-v2.sh && chmod +x /usr/local/bin/skill-scan-v2.sh
```

---

## 📄 License

MIT — JXXR1
