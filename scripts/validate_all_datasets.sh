#!/bin/bash
# Comprehensive dataset validation script

echo "=================================================="
echo " COMPREHENSIVE DATASET VALIDATION"
echo "=================================================="
echo ""

cd /Users/nessakodo/phishing-analyst

# Activate virtual environment
source venv/bin/activate

# Create timestamped results directory
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
RESULTS_DIR="results/validation_${TIMESTAMP}"
mkdir -p "$RESULTS_DIR"

echo "Results will be saved to: $RESULTS_DIR"
echo ""

# Test SpamAssassin Spam_2
echo "=================================================="
echo "Testing: SpamAssassin Spam Corpus 2"
echo "=================================================="
python3 standalone_triage.py \
    --dataset data/spamassassin/spam_2 \
    --ground-truth data/spamassassin/ground_truth.csv \
    --output "$RESULTS_DIR/spamassassin_spam2.json" \
    --no-llm \
    --max-emails 500

# Test SpamAssassin Easy Ham
echo ""
echo "=================================================="
echo "Testing: SpamAssassin Easy Ham"
echo "=================================================="
python3 standalone_triage.py \
    --dataset data/spamassassin/easy_ham \
    --ground-truth data/spamassassin/easy_ham_ground_truth.csv \
    --output "$RESULTS_DIR/spamassassin_easy_ham.json" \
    --no-llm \
    --max-emails 500

# Test Combined Dataset
echo ""
echo "=================================================="
echo "Testing: Combined Test Dataset"
echo "=================================================="
python3 standalone_triage.py \
    --dataset data/combined_test \
    --ground-truth data/combined_test/ground_truth.csv \
    --output "$RESULTS_DIR/combined_test.json" \
    --no-llm \
    --max-emails 500

# Test Ling-Spam (sample)
echo ""
echo "=================================================="
echo "Testing: Ling-Spam Corpus (Sample)"
echo "=================================================="
python3 standalone_triage.py \
    --dataset data/ling_spam/lingspam_public \
    --ground-truth data/ling_spam/ground_truth.csv \
    --output "$RESULTS_DIR/ling_spam.json" \
    --no-llm \
    --max-emails 500

echo ""
echo "=================================================="
echo " ALL TESTS COMPLETE"
echo "=================================================="
echo "Results saved to: $RESULTS_DIR"
echo ""
echo "To view summary:"
echo "  python3 scripts/summarize_results.py $RESULTS_DIR"
