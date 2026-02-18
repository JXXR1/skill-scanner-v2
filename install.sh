#!/bin/bash
# Skill Scanner v2 Installation Script
# Author: EVE (OpenClaw Security)
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
    $SUDO apt update
    $SUDO apt install -y yara firejail jq curl
elif command -v yum &> /dev/null; then
    $SUDO yum install -y yara firejail jq curl
elif command -v brew &> /dev/null; then
    brew install yara firejail jq curl
else
    echo "⚠️  Package manager not recognized. Please install manually:"
    echo "   - yara"
    echo "   - firejail"
    echo "   - jq"
    echo "   - curl"
    exit 1
fi

# 2. Install scanner script
echo ""
echo "📝 Installing scanner script..."
$SUDO cp skill-scan-v2.sh /usr/local/bin/
$SUDO chmod +x /usr/local/bin/skill-scan-v2.sh
echo "   ✅ Installed to: /usr/local/bin/skill-scan-v2.sh"

# 3. Install YARA rules
echo ""
echo "🔍 Installing YARA rules..."
$SUDO mkdir -p /var/lib/yara/rules
$SUDO cp openclaw-malware.yar /var/lib/yara/rules/
echo "   ✅ Installed to: /var/lib/yara/rules/openclaw-malware.yar"

# 4. Verify installation
echo ""
echo "✅ Installation complete!"
echo ""
echo "Usage:"
echo "  skill-scan-v2.sh /path/to/skill"
echo "  skill-scan-v2.sh skill-name"
echo ""
echo "Run certification test:"
echo "  cd test-suite && bash run-certification.sh"
echo ""
echo "Documentation:"
echo "  https://github.com/YOUR_ORG/skill-scanner-v2"
