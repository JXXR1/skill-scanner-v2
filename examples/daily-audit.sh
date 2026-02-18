#!/bin/bash
# Daily skill audit script
# Install to /etc/cron.daily/skill-audit (requires root)
# Or add to crontab: 0 3 * * * /path/to/daily-audit.sh

LOG_FILE="/var/log/skill-audit-$(date +%Y-%m-%d).log"
ALERT_EMAIL="admin@example.com"  # Change this
SKILLS_DIR="/opt/clawdbot/skills"  # Change if needed

echo "=== Skill Security Audit ===" | tee "$LOG_FILE"
echo "Date: $(date)" | tee -a "$LOG_FILE"
echo "" | tee -a "$LOG_FILE"

TOTAL=0
CLEAN=0
SUSPICIOUS=0
MALICIOUS=0

for skill in "$SKILLS_DIR"/*; do
  if [ ! -d "$skill" ]; then continue; fi
  
  SKILL_NAME=$(basename "$skill")
  ((TOTAL++))
  
  echo "Scanning: $SKILL_NAME" | tee -a "$LOG_FILE"
  
  skill-scan-v2.sh "$skill" >> "$LOG_FILE" 2>&1
  EXIT_CODE=$?
  
  if [ $EXIT_CODE -eq 0 ]; then
    echo "  ✅ Clean" | tee -a "$LOG_FILE"
    ((CLEAN++))
  elif [ $EXIT_CODE -ge 10 ]; then
    echo "  🚫 MALICIOUS" | tee -a "$LOG_FILE"
    ((MALICIOUS++))
  else
    echo "  ⚠️  Suspicious" | tee -a "$LOG_FILE"
    ((SUSPICIOUS++))
  fi
  
  echo "" | tee -a "$LOG_FILE"
done

echo "========================================" | tee -a "$LOG_FILE"
echo "Summary:" | tee -a "$LOG_FILE"
echo "  Total scanned: $TOTAL" | tee -a "$LOG_FILE"
echo "  Clean: $CLEAN" | tee -a "$LOG_FILE"
echo "  Suspicious: $SUSPICIOUS" | tee -a "$LOG_FILE"
echo "  Malicious: $MALICIOUS" | tee -a "$LOG_FILE"

# Send email alert if malicious skills found
if [ $MALICIOUS -gt 0 ] && command -v mail &> /dev/null; then
  echo "🚨 MALICIOUS SKILLS DETECTED" | mail -s "Security Alert: Malicious Skills" "$ALERT_EMAIL"
fi

# Exit with error if malicious found
[ $MALICIOUS -eq 0 ]
