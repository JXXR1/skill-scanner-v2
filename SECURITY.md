# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 3.x     | ✅ Active  |
| 2.x     | ❌ EOL     |
| < 2.0   | ❌ EOL     |

## Reporting a Vulnerability

If you discover a vulnerability in Skill Scanner itself (e.g. a bypass technique, false negative class, or sandbox escape):

1. **Do not open a public issue.**
2. Open a [GitHub Security Advisory](https://github.com/JXXR1/skill-scanner-v2/security/advisories/new) (private disclosure).
3. Include:
   - Description of the bypass or vulnerability
   - A minimal skill that demonstrates the gap
   - Suggested fix if you have one

Expect a response within 48 hours.

## Scope

In scope:
- Detection bypass techniques (false negatives across any of the 28 modules)
- Sandbox escape from the firejail module (#18)
- YARA rule weaknesses
- AST taint tracking gaps (#27)
- LLM semantic analysis prompt injection (#28)

Out of scope:
- False positives (open a regular issue)
- Feature requests (open a regular issue)
- The Cisco Skill Scanner — report those upstream

## Philosophy

This tool exists to protect AI agent deployments. Any gap that lets a malicious skill evade detection is treated as a critical vulnerability.
