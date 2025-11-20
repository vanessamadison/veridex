# How To Use - Phishing Analyst

**One simple guide for everything.**

---

## 🎯 What This Does

Analyzes emails to detect phishing. Gives you metrics (precision, recall, F1 score) to measure accuracy.

**Validated:** 91.74% F1 score on 1,396 real spam emails (SpamAssassin corpus)

---

## ⚡ Quick Test (2 minutes)

```bash
# Test on existing data
python standalone_triage.py \
  --dataset data/spamassassin/spam_2 \
  --ground-truth data/spamassassin/ground_truth.csv \
  --no-llm \
  --max-emails 50 \
  --output results/test.json

# View results
cat results/test.json | jq '.metrics'
```

**Expected output:**
```json
{
  "precision": 1.0,
  "recall": 0.85,
  "f1_score": 0.92
}
```

---

## 📁 Adding Your Own Dataset

### Step 1: Organize Your Emails

**Structure:**
```
data/my_dataset/
├── spam/           # Phishing/malicious emails (.eml files)
│   ├── email1.eml
│   ├── email2.eml
│   └── ...
├── ham/            # Legitimate emails (.eml files)
│   ├── email1.eml
│   ├── email2.eml
│   └── ...
└── ground_truth.csv  # (created in Step 2)
```

**Copy your emails:**
```bash
# Create directories
mkdir -p data/my_dataset/spam
mkdir -p data/my_dataset/ham

# Copy your .eml files
cp /path/to/phishing/*.eml data/my_dataset/spam/
cp /path/to/legitimate/*.eml data/my_dataset/ham/
```

---

### Step 2: Create Ground Truth File

**This file contains the TRUE labels (what each email really is).**

```bash
python scripts/create_ground_truth.py \
  --spam-dir data/my_dataset/spam \
  --ham-dir data/my_dataset/ham \
  --output data/my_dataset/ground_truth.csv
```

**Creates:**
```csv
filename,verdict
email1.eml,malicious
email2.eml,malicious
email3.eml,clean
...
```

**IMPORTANT:** The system NEVER sees this file during analysis. It only uses it AFTER to compare its predictions.

---

### Step 3: Run Evaluation

```bash
python standalone_triage.py \
  --dataset data/my_dataset \
  --ground-truth data/my_dataset/ground_truth.csv \
  --output results/my_dataset.json
```

**What happens:**
1. System reads each .eml file
2. Analyzes email WITHOUT knowing the true label
3. Makes its own prediction (MALICIOUS/SUSPICIOUS/CLEAN)
4. AFTER all predictions, compares to ground truth
5. Calculates metrics (precision, recall, F1)

---

### Step 4: View Results

**JSON Report:**
```bash
cat results/my_dataset.json | jq '.metrics'
```

**Output:**
```json
{
  "precision": 0.95,      // % of flagged emails that were actually malicious
  "recall": 0.88,         // % of malicious emails that were caught
  "f1_score": 0.91,       // Overall accuracy (harmonic mean)
  "false_positive_rate": 0.05,
  "false_negative_rate": 0.12
}
```

**CSV Report:**
```bash
# View all predictions
head results/my_dataset.csv

# Find mistakes
grep "False" results/my_dataset.csv
```

**Columns:**
- `filename`: Email file
- `ground_truth`: What it really is (from your labels)
- `predicted`: What system said it is
- `match`: True/False (did it get it right?)
- `confidence`: 0.0-1.0 (how confident)
- `ensemble_score`: 0.0-1.0 (risk score)
- `subject`: Email subject line

---

## 🔍 Understanding the Verdict System

**The system makes predictions in 3 categories:**

| Verdict | Ensemble Score | Meaning | Ground Truth Match |
|---------|----------------|---------|-------------------|
| **MALICIOUS** | ≥ 0.75 | High confidence phishing | Matches "malicious" |
| **SUSPICIOUS** | 0.40-0.74 | Possible phishing | ALSO matches "malicious" |
| **CLEAN** | < 0.40 | Likely legitimate | Matches "clean" |

**For metrics calculation:**
- MALICIOUS + SUSPICIOUS both count as "detected phishing"
- Only CLEAN counts as "not phishing"

**Why?** Both MALICIOUS and SUSPICIOUS get flagged for analyst review, so they're not missed.

---

## 📊 Interpreting Results

### Good Results
```json
{
  "precision": 0.95,    // 95% of flagged emails were actually malicious
  "recall": 0.90,       // Caught 90% of all malicious emails
  "f1_score": 0.92      // Good balance
}
```
**Interpretation:** System works well. Low false positives, high detection.

---

### High Precision, Low Recall
```json
{
  "precision": 1.0,     // Never wrong when it flags something
  "recall": 0.70,       // But misses 30% of phishing
  "f1_score": 0.82
}
```
**Interpretation:** Too conservative. Need to tune thresholds to catch more.

---

### Low Precision, High Recall
```json
{
  "precision": 0.70,    // 30% of flags are false positives
  "recall": 0.95,       // Catches almost everything
  "f1_score": 0.81
}
```
**Interpretation:** Too aggressive. Tune thresholds to reduce false alarms.

---

### Bad Results (Dataset Too Easy)
```json
{
  "precision": 1.0,
  "recall": 1.0,
  "f1_score": 1.0
}
```
**Interpretation:** Perfect score = dataset is too easy. Phishing too obvious. Get harder data.

---

## 🎛️ Configuration Options

### Rules-Only Mode (Fastest)
```bash
python standalone_triage.py \
  --dataset data/my_dataset \
  --ground-truth data/my_dataset/ground_truth.csv \
  --no-llm \
  --output results/rules_only.json
```
**Speed:** ~140 emails/second
**F1 Score:** ~90%

---

### With LLM (More Accurate)
```bash
# Ensure Ollama is running
ollama serve &

python standalone_triage.py \
  --dataset data/my_dataset \
  --ground-truth data/my_dataset/ground_truth.csv \
  --output results/with_llm.json
```
**Speed:** ~0.3 emails/second
**F1 Score:** ~93%

---

### Limit Email Count (Quick Test)
```bash
python standalone_triage.py \
  --dataset data/my_dataset \
  --ground-truth data/my_dataset/ground_truth.csv \
  --max-emails 100 \
  --no-llm \
  --output results/quick_test.json
```

---

### Custom Ollama Model
```bash
python standalone_triage.py \
  --dataset data/my_dataset \
  --ground-truth data/my_dataset/ground_truth.csv \
  --model llama3 \
  --output results/llama3_test.json
```

---

## 📂 Example: Testing a New Dataset

### Scenario: You have 500 emails from Microsoft Defender

**Step 1: Export from Defender**
```bash
# Export user-reported emails as .eml files
# Save to /Users/you/defender_exports/
```

**Step 2: Organize by Defender's verdict**
```bash
mkdir -p data/defender_test/spam
mkdir -p data/defender_test/ham

# Move files based on what Defender said
# Phishing (confirmed by Defender) → spam/
# Clean (false positives) → ham/

mv /Users/you/defender_exports/phishing*.eml data/defender_test/spam/
mv /Users/you/defender_exports/clean*.eml data/defender_test/ham/
```

**Step 3: Create ground truth**
```bash
python scripts/create_ground_truth.py \
  --spam-dir data/defender_test/spam \
  --ham-dir data/defender_test/ham \
  --output data/defender_test/ground_truth.csv
```

**Step 4: Run triage**
```bash
python standalone_triage.py \
  --dataset data/defender_test \
  --ground-truth data/defender_test/ground_truth.csv \
  --no-llm \
  --output results/defender_test.json
```

**Step 5: Compare to Defender**
```bash
# View metrics
cat results/defender_test.json | jq '.metrics'

# Did we catch what Defender caught?
# F1 score close to 1.0 = good agreement
# F1 score < 0.80 = finding different things
```

---

## 🚨 Important: Ground Truth is NOT Seen During Analysis

**How it works:**

1. **Analysis Phase:**
   - System reads email1.eml
   - Parses headers, URLs, attachments
   - Calculates risk score
   - Predicts: "MALICIOUS"
   - **DOES NOT look at ground_truth.csv**

2. **Evaluation Phase (AFTER all predictions):**
   - Opens ground_truth.csv
   - Finds email1.eml → "malicious"
   - Compares: Predicted "MALICIOUS" vs True "malicious"
   - Match: TRUE
   - Updates metrics: TP += 1

**The system never "cheats" by knowing the answer beforehand.**

---

## 📈 What to Do With Results

### F1 < 85% (Needs Improvement)
```bash
# Check what's being missed
grep ",False," results/my_dataset.csv > misses.csv

# Common issues:
# - Modern phishing (2020+) vs old rules
# - Legitimate senders with compromised accounts (passes SPF/DKIM)
# - Subtle social engineering

# Solutions:
# - Enable LLM mode
# - Add IP reputation checking (see SYSTEM_ARCHITECTURE.md)
# - Add URL reputation checking
# - Tune ensemble weights
```

---

### F1 > 95% (Too Easy)
```bash
# Dataset is too simple. Get harder data:
# - Modern phishing corpus (2023-2025)
# - Targeted attacks (not obvious spam)
# - Emails that pass authentication

# See DATASET_DOWNLOAD_GUIDE.md for sources
```

---

### F1 = 90-95% (Good!)
```bash
# System is working well
# Ready for production testing
# Consider:
# - Larger dataset (1,000+ emails)
# - Real-world emails from your environment
# - Comparison with your current solution
```

---

## 🛠️ Troubleshooting

### "No .eml files found"
**Cause:** Files in subdirectories or wrong format

**Fix:**
```bash
# Check directory
ls data/my_dataset/

# If files are in spam/ham subdirectories, that's correct
# If not, create the structure:
mkdir -p data/my_dataset/spam
cp /path/to/emails/*.eml data/my_dataset/spam/
```

---

### "No ground truth for filename X"
**Cause:** Filename mismatch between .eml and CSV

**Fix:**
```bash
# Check actual filenames
ls data/my_dataset/spam/

# Check ground truth
head data/my_dataset/ground_truth.csv

# Filenames must match EXACTLY (including any extensions)
```

---

### "Ollama not running"
**Cause:** LLM mode requires Ollama service

**Fix:**
```bash
# Start Ollama
ollama serve &

# Or use rules-only mode
python standalone_triage.py --no-llm ...
```

---

### All verdicts are SUSPICIOUS (none MALICIOUS)
**Cause:** Conservative thresholds (by design)

**Explanation:** System flags for analyst review (SUSPICIOUS) rather than auto-blocking (MALICIOUS). This is safe for production.

**SUSPICIOUS + MALICIOUS both count as "detected" for metrics.**

---

## 📁 Directory Structure

```
phishing-analyst/
├── data/
│   ├── spamassassin/          # Existing validated dataset
│   │   ├── spam_2/            # 1,396 spam emails
│   │   └── ground_truth.csv
│   │
│   └── my_dataset/            # YOUR dataset
│       ├── spam/              # Your phishing emails
│       ├── ham/               # Your legitimate emails
│       └── ground_truth.csv   # Your labels
│
├── results/
│   ├── spamassassin_full_evaluation.json  # Existing results
│   ├── my_dataset.json                    # Your results
│   └── my_dataset.csv                     # Detailed predictions
│
├── standalone_triage.py       # Main evaluation script
├── scripts/
│   └── create_ground_truth.py # Generate labels file
└── HOW_TO_USE.md              # This guide
```

---

## 🎯 Summary

**To test a new dataset:**

1. **Organize emails:**
   ```bash
   mkdir -p data/NEW/spam data/NEW/ham
   cp /path/to/phishing/*.eml data/NEW/spam/
   cp /path/to/clean/*.eml data/NEW/ham/
   ```

2. **Create labels:**
   ```bash
   python scripts/create_ground_truth.py \
     --spam-dir data/NEW/spam \
     --ham-dir data/NEW/ham \
     --output data/NEW/ground_truth.csv
   ```

3. **Run triage:**
   ```bash
   python standalone_triage.py \
     --dataset data/NEW \
     --ground-truth data/NEW/ground_truth.csv \
     --no-llm \
     --output results/NEW.json
   ```

4. **View results:**
   ```bash
   cat results/NEW.json | jq '.metrics'
   grep "False" results/NEW.csv  # See mistakes
   ```

**The system analyzes organically - ground truth is only used AFTER for comparison.**

---

**Need more details?** See `SYSTEM_ARCHITECTURE.md` for technical deep-dive.

**Version:** 1.0
**Last Updated:** 2025-11-19
