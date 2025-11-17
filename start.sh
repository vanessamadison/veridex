#!/bin/bash
# Email Triage Automation System - Startup Script
# HIPAA-Compliant SOC Decision Support

set -e

echo "============================================"
echo "  Email Triage Automation System"
echo "  HIPAA-Compliant SOC Decision Support"
echo "============================================"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Get script directory
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
cd "$SCRIPT_DIR"

# Check Python
echo -e "\n${YELLOW}[1/6] Checking Python...${NC}"
if command -v python3 &> /dev/null; then
    PYTHON_VERSION=$(python3 --version)
    echo -e "${GREEN}✓ $PYTHON_VERSION${NC}"
else
    echo -e "${RED}✗ Python 3 not found. Please install Python 3.8+${NC}"
    exit 1
fi

# Check/Install Dependencies
echo -e "\n${YELLOW}[2/6] Checking dependencies...${NC}"
if [ ! -f "venv/bin/activate" ]; then
    echo "Creating virtual environment..."
    python3 -m venv venv
fi

source venv/bin/activate

# Install requirements
if [ -f "requirements.txt" ]; then
    echo "Installing dependencies..."
    pip install -q -r requirements.txt
    echo -e "${GREEN}✓ Dependencies installed${NC}"
else
    echo -e "${RED}✗ requirements.txt not found${NC}"
    exit 1
fi

# Check Ollama
echo -e "\n${YELLOW}[3/6] Checking Ollama...${NC}"
if command -v ollama &> /dev/null; then
    if curl -s http://localhost:11434/api/tags > /dev/null 2>&1; then
        MODELS=$(curl -s http://localhost:11434/api/tags | python3 -c "import sys, json; print(', '.join([m['name'] for m in json.load(sys.stdin).get('models', [])]))")
        echo -e "${GREEN}✓ Ollama running - Models: $MODELS${NC}"
    else
        echo -e "${YELLOW}⚠ Ollama not running. Starting...${NC}"
        ollama serve &
        sleep 3
        echo -e "${GREEN}✓ Ollama started${NC}"
    fi
else
    echo -e "${RED}✗ Ollama not installed. Install from: https://ollama.ai${NC}"
    echo "  The system will run in rule-based mode (no LLM analysis)"
fi

# Verify config
echo -e "\n${YELLOW}[4/6] Verifying configuration...${NC}"
if [ -f "config/config.yaml" ]; then
    echo -e "${GREEN}✓ Configuration found${NC}"
else
    echo -e "${YELLOW}⚠ config/config.yaml not found. Creating default...${NC}"
    mkdir -p config
    cat > config/config.yaml << 'EOF'
# Email Triage Automation Configuration
# HIPAA-Compliant Settings

ollama:
  model: "mistral:latest"
  base_url: "http://localhost:11434"
  temperature: 0.1
  timeout: 30
  use_ollama: true

ensemble:
  weights:
    ollama: 0.40
    rules: 0.30
    defender: 0.30
  thresholds:
    auto_block: 0.90
    malicious: 0.75
    suspicious: 0.40
    clean: 0.15
    auto_resolve_clean: 0.10

hipaa:
  enforce: true
  audit_retention_days: 2190  # 6 years
  exclude_body: true
  body_preview_max_chars: 50
  log_all_decisions: true

internal_domains:
  - "example-healthcare.org"
  - "campus-university.edu"
  - "internal-corp.com"

logging:
  level: "INFO"
  audit_path: "results/audit"
  rotation_days: 30
EOF
    echo -e "${GREEN}✓ Default configuration created${NC}"
fi

# Create results directory
echo -e "\n${YELLOW}[5/6] Preparing results directory...${NC}"
mkdir -p results/audit
echo -e "${GREEN}✓ Results directory ready${NC}"

# Test core imports
echo -e "\n${YELLOW}[6/6] Testing core modules...${NC}"
python3 << 'EOF'
import sys
sys.path.insert(0, '.')
try:
    from src.core.mdo_field_extractor import MDOFieldExtractor
    from src.generators.ollama_email_generator import OllamaEmailGenerator
    from src.auth.security import user_store
    print("✓ Core modules loaded successfully")
except ImportError as e:
    print(f"✗ Import error: {e}")
    sys.exit(1)
EOF

echo -e "\n${GREEN}============================================${NC}"
echo -e "${GREEN}  System Ready!${NC}"
echo -e "${GREEN}============================================${NC}"

echo -e "\nStarting FastAPI server..."
echo -e "Dashboard: ${GREEN}http://127.0.0.1:8000/dashboard${NC}"
echo -e "API Docs:  ${GREEN}http://127.0.0.1:8000/docs${NC}"
echo -e "Health:    ${GREEN}http://127.0.0.1:8000/health${NC}"

echo -e "\n${YELLOW}Default Login:${NC}"
echo "  Username: admin"
echo "  Password: changeme123"
echo -e "\n${RED}⚠ CHANGE DEFAULT PASSWORD IMMEDIATELY${NC}"

echo -e "\nPress Ctrl+C to stop the server\n"

# Start server
python3 -m uvicorn src.api.main:app --host 127.0.0.1 --port 8000 --reload
