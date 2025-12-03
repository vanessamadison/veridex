#!/bin/bash
# Corrected validation script with proper paths

echo "=================================================="
echo " CORRECTED DATASET VALIDATION"
echo "=================================================="

# Get script directory and navigate to project root
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
cd "$SCRIPT_DIR/.."

# Activate virtual environment if it exists
if [ -d "venv" ]; then
    source venv/bin/activate
fi

TIMESTAMP=$(date +%Y%m%d_%H%M%S)
RESULTS_DIR="results/validation_corrected_${TIMESTAMP}"
mkdir -p "$RESULTS_DIR"

echo "Results: $RESULTS_DIR"

# Test Combined - Spam
echo "Testing: Combined Test - Spam"
python3 standalone_triage.py \
    --dataset data/combined_test/spam \
    --ground-truth data/combined_test/ground_truth.csv \
    --output "$RESULTS_DIR/combined_spam.json" \
    --no-llm \
    --max-emails 500

# Test Combined - Ham  
echo "Testing: Combined Test - Ham"
python3 standalone_triage.py \
    --dataset data/combined_test/ham \
    --ground-truth data/combined_test/ground_truth.csv \
    --output "$RESULTS_DIR/combined_ham.json" \
    --no-llm \
    --max-emails 500

# Test Ling-Spam
echo "Testing: Ling-Spam"
python3 standalone_triage.py \
    --dataset data/ling_spam/lingspam_public/bare/part1 \
    --ground-truth data/ling_spam/ground_truth.csv \
    --output "$RESULTS_DIR/ling_spam.json" \
    --no-llm \
    --max-emails 500

echo "Complete! Results in: $RESULTS_DIR"
