#!/bin/bash
# Skill Scanner v2 Installation Script
# Author: JXXR1
# License: MIT

set -e

echo "=== Skill Scanner v2 Installation ==="
echo ""

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo "⚠️  Not running as root. Some installations may require sudo."
    SUDO="sudo"
else
    SUDO=""
fi

# 1. Install system dependencies
echo "📦 Installing system dependencies..."
if command -v apt &> /dev/null; then
    $SUDO apt update -qq
    $SUDO apt install -y yara firejail jq python3
elif command -v yum &> /dev/null; then
    $SUDO yum install -y yara firejail jq python3
elif command -v brew &> /dev/null; then
    brew install yara jq python3
    echo "   ℹ️  firejail not available on macOS — sandbox tests will be skipped"
else
    echo "⚠️  Package manager not recognised. Install these manually:"
    echo "   Required:  python3, jq"
    echo "   Optional:  yara (signature scanning), firejail (sandbox testing)"
fi

# 2. Install scanner script
echo ""
echo "📝 Installing scanner..."
$SUDO cp skill-scan-v2.sh /usr/local/bin/
$SUDO chmod +x /usr/local/bin/skill-scan-v2.sh
echo "   ✅ /usr/local/bin/skill-scan-v2.sh"

# 3. Install YARA rules
echo ""
echo "🔍 Installing YARA rules..."
$SUDO mkdir -p /var/lib/yara/rules
$SUDO cp openclaw-malware.yar /var/lib/yara/rules/
echo "   ✅ /var/lib/yara/rules/openclaw-malware.yar"

# 4. Check optional LLM backend
echo ""
echo "🧠 Checking LLM backend (optional — for --llm flag)..."
if curl -s --max-time 2 http://localhost:11434/api/tags >/dev/null 2>&1; then
    OLLAMA_MODEL=$(curl -s http://localhost:11434/api/tags | python3 -c \
        "import json,sys; models=json.load(sys.stdin).get('models',[]); print(models[0]['name'] if models else 'none')" 2>/dev/null)
    echo "   ✅ Ollama running — model: ${OLLAMA_MODEL:-detected}"
    echo "   ℹ️  LLM analysis will run locally (no data leaves this machine)"
elif [ -n "$ANTHROPIC_API_KEY" ]; then
    echo "   ✅ ANTHROPIC_API_KEY set — Anthropic API will be used as fallback"
    echo "   ⚠️  Skill content will be sent to Anthropic's servers when --llm is used"
else
    echo "   ℹ️  No LLM backend detected — --llm flag will prompt setup instructions"
    echo ""
    echo "   To enable local LLM analysis (recommended):"
    echo "     curl -fsSL https://ollama.com/install.sh | sh"
    echo "     ollama pull llama3"
    echo ""
    echo "   To enable cloud LLM analysis:"
    echo "     export ANTHROPIC_API_KEY=sk-ant-..."
fi

# 5. Verify
echo ""
echo "=== Installation complete ==="
echo ""
echo "Usage:"
echo "  skill-scan-v2.sh /path/to/skill              # standard scan (26 modules)"
echo "  skill-scan-v2.sh /path/to/skill --llm        # + LLM semantic analysis"
echo "  skill-scan-v2.sh /path/to/skill --llm --yes  # skip confirmation"
echo ""
echo "Exit codes:  0 = clean  |  1-9 = suspicious  |  10+ = malicious"
echo ""
echo "Certification test:"
echo "  cd test-suite && bash run-certification.sh"
echo ""
echo "Docs:  https://github.com/JXXR1/skill-scanner-v2"
