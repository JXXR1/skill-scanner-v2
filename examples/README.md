# Integration Examples

This directory contains example scripts and configurations for integrating Skill Scanner v2 into your workflow.

---

## 📁 Files

### `pre-commit`
Git pre-commit hook that blocks commits containing malicious code.

**Setup:**
```bash
cp examples/pre-commit .git/hooks/pre-commit
chmod +x .git/hooks/pre-commit
```

**Behavior:**
- ✅ Clean (exit 0): Commit proceeds
- ⚠️ Suspicious (exit 1-9): Prompts user for confirmation
- 🚫 Malicious (exit 10+): Blocks commit

---

### `daily-audit.sh`
Automated daily security audit of all installed skills.

**Setup (cron):**
```bash
sudo cp examples/daily-audit.sh /usr/local/bin/
sudo chmod +x /usr/local/bin/daily-audit.sh
sudo crontab -e
```

Add:
```cron
0 3 * * * /usr/local/bin/daily-audit.sh
```

**Setup (systemd timer):**
```bash
sudo cp examples/daily-audit.sh /usr/local/bin/
sudo systemctl enable --now daily-skill-audit.timer
```

**Configuration:**
- Edit `ALERT_EMAIL` to receive alerts
- Edit `SKILLS_DIR` if skills are in a different location
- Logs saved to `/var/log/skill-audit-YYYY-MM-DD.log`

---

### `github-actions.yml`
GitHub Actions workflow for automated security scanning in CI/CD.

**Setup:**
```bash
mkdir -p .github/workflows
cp examples/github-actions.yml .github/workflows/security-scan.yml
git add .github/workflows/security-scan.yml
git commit -m "Add security scanning to CI"
git push
```

**Features:**
- Runs on every push and pull request
- Blocks merge if malicious code detected
- Comments on PRs with scan results
- Uploads scan logs as artifacts

**Customization:**
- Change `YOUR_ORG` to your GitHub organization
- Adjust branch triggers (`main`, `develop`)
- Modify notification behavior in PR comments

---

## 🎯 Use Cases

### 1. Development Workflow
**Goal:** Prevent developers from committing malicious code

**Solution:** Pre-commit hook
```bash
cp examples/pre-commit .git/hooks/pre-commit
chmod +x .git/hooks/pre-commit
```

---

### 2. Production Monitoring
**Goal:** Daily audits of all installed skills

**Solution:** Daily audit cron job
```bash
sudo cp examples/daily-audit.sh /usr/local/bin/
echo "0 3 * * * /usr/local/bin/daily-audit.sh" | sudo crontab -
```

---

### 3. CI/CD Pipeline
**Goal:** Automated scanning in pull requests

**Solution:** GitHub Actions workflow
```bash
cp examples/github-actions.yml .github/workflows/security-scan.yml
```

---

### 4. Manual Review Process
**Goal:** Scan skill before installing from untrusted source

**Solution:** Run scanner manually
```bash
git clone https://github.com/untrusted/suspicious-skill
skill-scan-v2.sh suspicious-skill && openclaw install suspicious-skill
```

---

### 5. Bulk Scanning
**Goal:** Scan all skills in a directory

**Solution:** Bash loop
```bash
for skill in /opt/clawdbot/skills/*; do
  skill-scan-v2.sh "$skill" || echo "⚠️ $skill flagged"
done
```

---

## 🔧 Customization Tips

### Adjust Sensitivity

Edit `skill-scan-v2.sh` to change detection thresholds:

```bash
# Original (strict):
if [ $ISSUES -ge 10 ]; then
  echo "MALICIOUS"
  exit 10
fi

# Modified (lenient):
if [ $ISSUES -ge 15 ]; then  # Raise threshold
  echo "MALICIOUS"
  exit 10
fi
```

### Add Custom Patterns

Add to `skill-scan-v2.sh`:

```bash
# Custom check
echo "=== Custom Corporate Policy ==="
if grep -rE "company-secret-key" "$SKILL_PATH" 2>/dev/null; then
  echo "🚫 COMPANY SECRET LEAKED"
  ((ISSUES+=10))
else
  echo "✅ No secrets leaked"
fi
```

### Integrate with Slack

Modify `daily-audit.sh`:

```bash
# At end of script
if [ $MALICIOUS -gt 0 ]; then
  curl -X POST -H 'Content-type: application/json' \
    --data "{\"text\":\"🚨 $MALICIOUS malicious skills detected!\"}" \
    https://hooks.slack.com/services/YOUR/WEBHOOK/URL
fi
```

---

## 📞 Support

Questions? Issues?

- **GitHub Issues:** https://github.com/YOUR_ORG/skill-scanner-v2/issues
- **OpenClaw Discord:** https://discord.com/invite/clawd
- **Documentation:** https://github.com/YOUR_ORG/skill-scanner-v2

---

**Integrate once. Protect forever.** 🛡️
