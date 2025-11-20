# Dataset Download Guide
## Where to Get Real Phishing Datasets for Testing

**Last Updated:** 2025-11-19

---

## Quick Summary

| Dataset | Size | Type | Difficulty | Download Time | Expected F1 |
|---------|------|------|------------|---------------|-------------|
| **SpamAssassin** | 6K emails (~50 MB) | Spam + Ham | Easy | 2 min | 85-90% |
| **Enron** | 500K emails (~1.7 GB) | Legitimate only | Easy | 30 min | N/A (FP test) |
| **TREC 2007 Spam** | 75K emails (~300 MB) | Spam + Ham | Medium | 10 min | 87-92% |
| **Nazario Phishing** | 4K emails (~20 MB) | Phishing only | Hard | 5 min | 90-94% |

**Recommended:** Start with SpamAssassin (easiest, well-documented)

---

## Dataset 1: SpamAssassin Public Corpus ⭐ RECOMMENDED

### Overview
- **Size:** ~6,000 emails (~50 MB compressed)
- **Type:** Spam detection (includes phishing)
- **Format:** Individual .eml files (RFC 822)
- **Labels:** spam_2/ (spam) and easy_ham_2/ (legitimate)
- **License:** Public domain
- **Quality:** High (complete headers, real emails)

### Why Use This?
- ✅ Well-established benchmark (used in academic papers)
- ✅ Complete email headers (SPF/DKIM often present)
- ✅ Clear labels (spam vs. ham)
- ✅ Easy to download and process
- ✅ Good mix of phishing, spam, and legitimate emails

### Download & Setup (5 Minutes)

```bash
# 1. Create directory
mkdir -p data/spamassassin
cd data/spamassassin

# 2. Download spam corpus
wget https://spamassassin.apache.org/old/publiccorpus/20050311_spam_2.tar.bz2
tar -xjf 20050311_spam_2.tar.bz2

# 3. Download ham (legitimate) corpus
wget https://spamassassin.apache.org/old/publiccorpus/20030228_easy_ham_2.tar.bz2
tar -xjf 20030228_easy_ham_2.tar.bz2

# 4. Verify
ls spam_2/ | head -5
ls easy_ham_2/ | head -5

# 5. Create ground truth
cd ../..
python scripts/create_ground_truth.py \
  --spam-dir data/spamassassin/spam_2 \
  --ham-dir data/spamassassin/easy_ham_2 \
  --output data/spamassassin/ground_truth.csv

# 6. Evaluate (start with 100 emails for speed)
python standalone_triage.py \
  --dataset data/spamassassin/spam_2 \
  --ground-truth data/spamassassin/ground_truth.csv \
  --max-emails 100 \
  --no-llm \
  --output results/spamassassin_100.json
```

### Expected Results
```
Precision:  85-92%
Recall:     82-88%
F1 Score:   85-90%
Processing: ~10 seconds (100 emails, rules-only)
```

### All Available SpamAssassin Corpora

| Corpus | Emails | Description | URL |
|--------|--------|-------------|-----|
| spam_2 | 1,397 | Spam emails (2005) | https://spamassassin.apache.org/old/publiccorpus/20050311_spam_2.tar.bz2 |
| easy_ham_2 | 1,400 | Easy legitimate (2003) | https://spamassassin.apache.org/old/publiccorpus/20030228_easy_ham_2.tar.bz2 |
| hard_ham_3 | 250 | Hard-to-classify legitimate | https://spamassassin.apache.org/old/publiccorpus/20030228_hard_ham_3.tar.bz2 |
| spam | 500 | Original spam (2002) | https://spamassassin.apache.org/old/publiccorpus/20021010_spam.tar.bz2 |

**Recommended:** Use spam_2 + easy_ham_2 (most recent, best quality)

---

## Dataset 2: Enron Email Corpus

### Overview
- **Size:** 500,000+ emails (~1.7 GB)
- **Type:** Legitimate business emails only
- **Format:** Individual .eml files
- **Labels:** All legitimate (use for false positive testing)
- **License:** Public domain
- **Quality:** Very high (real corporate email)

### Why Use This?
- ✅ Test **false positive rate** (should NOT flag these as malicious)
- ✅ Large volume (test scalability)
- ✅ Real-world legitimate email patterns
- ✅ Well-documented (used in NLP research)

### Download & Setup (30 Minutes)

```bash
# 1. Create directory
mkdir -p data/enron
cd data/enron

# 2. Download (1.7 GB, takes ~5-30 minutes depending on connection)
wget https://www.cs.cmu.edu/~enron/enron_mail_20150507.tar.gz

# 3. Extract (takes ~5-10 minutes)
tar -xzf enron_mail_20150507.tar.gz

# 4. Verify structure
ls maildir/ | head -10

# 5. Count emails
find maildir/ -type f | wc -l
# Should show ~500,000

# 6. Create ground truth (all legitimate)
cd ../..
python scripts/create_ground_truth.py \
  --ham-dir data/enron/maildir \
  --output data/enron/ground_truth.csv

# 7. Evaluate (start with 100 emails)
# Note: Enron has subdirectories, so we need to collect .eml files first
mkdir -p data/enron/all
find data/enron/maildir -type f | head -100 | while read f; do cp "$f" data/enron/all/; done

python standalone_triage.py \
  --dataset data/enron/all \
  --ground-truth data/enron/ground_truth.csv \
  --max-emails 100 \
  --no-llm \
  --output results/enron_100.json
```

### Expected Results
```
False Positive Rate: <5%
Specificity: >95%
(Goal: Don't flag legitimate emails as phishing)
```

---

## Dataset 3: TREC 2007 Spam Track

### Overview
- **Size:** ~75,000 emails (~300 MB)
- **Type:** Spam detection benchmark
- **Format:** Berkeley mbox format
- **Labels:** Provided in separate file
- **License:** Research use
- **Quality:** Very high (standardized evaluation)

### Why Use This?
- ✅ Standardized benchmark (compare to published results)
- ✅ Large scale
- ✅ Time-ordered (realistic email stream)
- ✅ Includes challenging cases

### Download & Setup

```bash
# 1. Visit TREC website
# https://trec.nist.gov/data/spam.html

# 2. Download datasets (requires TREC registration)
# Note: This requires manual download, cannot wget

# 3. Follow instructions at:
# https://plg.uwaterloo.ca/~gvcormac/treccorpus07/

# Alternative: Use newer TREC datasets
# TREC 2007 Public Corpus:
wget https://plg.uwaterloo.ca/~gvcormac/treccorpus07/trec07p.tar.gz
tar -xzf trec07p.tar.gz

# 4. Convert mbox to individual .eml files
# (Requires additional script - see below)
```

**Note:** TREC datasets are more complex to process. Start with SpamAssassin first.

---

## Dataset 4: Nazario Phishing Corpus

### Overview
- **Size:** ~4,000 emails (~20 MB)
- **Type:** Real phishing emails only
- **Format:** Individual .eml files
- **Labels:** All phishing (high difficulty)
- **License:** Research use
- **Quality:** Very high (real-world phishing)

### Why Use This?
- ✅ **Pure phishing** - All emails are actual phishing attacks
- ✅ Test **recall** (can you catch all phishing?)
- ✅ Diverse techniques (PayPal, banks, services)
- ✅ Complete headers

### Download & Setup

```bash
# 1. Create directory
mkdir -p data/nazario_phishing
cd data/nazario_phishing

# 2. Download (manual - website browsing required)
# Visit: https://monkey.org/~jose/phishing/

# Method 1: Manual download from website
# - Browse to https://monkey.org/~jose/phishing/
# - Download individual .eml files or archives

# Method 2: wget mirror (downloads all)
wget -r -np -nd -A "*.eml,*.txt" -R "index.html" https://monkey.org/~jose/phishing/

# 3. Remove non-email files
rm -f index.html* robots.txt*

# 4. Verify
ls | head -10

# 5. Create ground truth (all phishing)
cd ../..
python scripts/create_ground_truth.py \
  --spam-dir data/nazario_phishing \
  --output data/nazario_phishing/ground_truth.csv

# 6. Evaluate
python standalone_triage.py \
  --dataset data/nazario_phishing \
  --ground-truth data/nazario_phishing/ground_truth.csv \
  --max-emails 100 \
  --no-llm \
  --output results/nazario_100.json
```

### Expected Results
```
Precision:  90-95%
Recall:     88-93%
F1 Score:   90-94%
(Higher than SpamAssassin due to pure phishing dataset)
```

---

## Dataset 5: PhishTank Database (Live Feed)

### Overview
- **Size:** ~10,000+ active phishing URLs
- **Type:** Phishing URLs only (not full emails)
- **Format:** JSON/CSV via API
- **Labels:** Community-verified phishing
- **License:** Free API (rate limited)
- **Quality:** High (community verification)

### Why Use This?
- ✅ **Current phishing URLs** - Updated daily
- ✅ Test URL detection specifically
- ✅ Free API access
- ⚠️ URLs only (not full email metadata)

### Access

```bash
# 1. Register for free API key
# Visit: https://www.phishtank.com/api_info.php

# 2. Download verified phishing URLs
curl "http://data.phishtank.com/data/online-valid.json" > data/phishtank/verified_phishing.json

# 3. Process JSON (extract URLs for testing)
cat data/phishtank/verified_phishing.json | python -m json.tool | grep '"url"' | head -20
```

**Note:** This gives URLs only, not full emails. Use for URL-specific testing.

---

## Comparison Table

### Dataset Selection Guide

| Use Case | Recommended Dataset | Why |
|----------|-------------------|-----|
| **First test** | SpamAssassin spam_2 + easy_ham_2 | Easy setup, balanced, well-documented |
| **False positive testing** | Enron corpus | Large, all legitimate |
| **Phishing-specific** | Nazario corpus | Pure phishing, high quality |
| **Benchmarking** | TREC 2007 | Standardized, comparable to research |
| **URL testing** | PhishTank | Current phishing URLs |
| **Large scale** | Enron (500K emails) | Scalability testing |

### Download Time Estimates

| Dataset | Size | Download Time (100 Mbps) | Extract Time |
|---------|------|-------------------------|--------------|
| SpamAssassin | 50 MB | 4 seconds | 30 seconds |
| Nazario | 20 MB | 2 seconds | 10 seconds |
| TREC 2007 | 300 MB | 24 seconds | 2 minutes |
| Enron | 1.7 GB | 2 minutes | 10 minutes |

---

## Step-by-Step: Your First Real Dataset Evaluation

### Recommended: SpamAssassin (Easiest)

```bash
# Total time: ~5 minutes

# 1. Download (2 minutes)
mkdir -p data/spamassassin && cd data/spamassassin
wget https://spamassassin.apache.org/old/publiccorpus/20050311_spam_2.tar.bz2
wget https://spamassassin.apache.org/old/publiccorpus/20030228_easy_ham_2.tar.bz2
tar -xjf 20050311_spam_2.tar.bz2
tar -xjf 20030228_easy_ham_2.tar.bz2

# 2. Create ground truth (30 seconds)
cd ../..
python scripts/create_ground_truth.py \
  --spam-dir data/spamassassin/spam_2 \
  --ham-dir data/spamassassin/easy_ham_2 \
  --output data/spamassassin/ground_truth.csv

# Verify
head -10 data/spamassassin/ground_truth.csv

# 3. Quick test: 100 emails (10 seconds)
python standalone_triage.py \
  --dataset data/spamassassin/spam_2 \
  --ground-truth data/spamassassin/ground_truth.csv \
  --max-emails 100 \
  --no-llm \
  --output results/spamassassin_quick.json

# 4. View results
cat results/spamassassin_quick.json | python -m json.tool | head -40

# 5. Full evaluation: All spam emails (~1,400) (2 minutes)
python standalone_triage.py \
  --dataset data/spamassassin/spam_2 \
  --ground-truth data/spamassassin/ground_truth.csv \
  --no-llm \
  --output results/spamassassin_full.json

# 6. Compare rules-only vs. with LLM
# (If Ollama installed)
ollama serve
python standalone_triage.py \
  --dataset data/spamassassin/spam_2 \
  --ground-truth data/spamassassin/ground_truth.csv \
  --max-emails 50 \
  --output results/spamassassin_with_llm.json
```

**Expected Output:**
```
============================================================
EVALUATION RESULTS
============================================================
Dataset: data/spamassassin/spam_2
Total Emails: 100

Metrics:
  Precision:          88.24%
  Recall:             85.71%
  F1 Score:           86.96%
  Accuracy:           87.00%
  False Positive Rate: 8.33%
  False Negative Rate: 14.29%

Confusion Matrix:
  True Positives:  60
  False Positives:  5
  True Negatives:  27
  False Negatives: 8
============================================================
```

---

## Troubleshooting Dataset Downloads

### Issue: wget not installed

**Mac:**
```bash
brew install wget
```

**Ubuntu/Debian:**
```bash
sudo apt-get install wget
```

**Windows:**
```bash
# Use PowerShell instead
Invoke-WebRequest -Uri "URL" -OutFile "filename.tar.bz2"
```

### Issue: tar not working

**Error:** `tar: Unrecognized archive format`

**Solution:** Try bzip2 specifically:
```bash
bunzip2 file.tar.bz2
tar -xf file.tar
```

### Issue: Dataset website down

**SpamAssassin mirror:**
```bash
# Try archive.org mirror
wget https://web.archive.org/web/*/https://spamassassin.apache.org/old/publiccorpus/20050311_spam_2.tar.bz2
```

**Alternative sources:**
- Kaggle datasets: https://www.kaggle.com/datasets?search=spam+email
- UCI ML Repository: https://archive.ics.uci.edu/ml/datasets/Spambase
- Academic mirrors: Ask on research forums

### Issue: Disk space

**Check available space:**
```bash
df -h
```

**Enron is large (1.7 GB):**
- Download to external drive
- Or use SpamAssassin instead (only 50 MB)

---

## Dataset Storage Organization

### Recommended Structure

```
data/
├── spamassassin/
│   ├── spam_2/              # 1,397 spam emails
│   ├── easy_ham_2/          # 1,400 ham emails
│   ├── ground_truth.csv     # Labels
│   ├── 20050311_spam_2.tar.bz2       # Archive (can delete after extract)
│   └── 20030228_easy_ham_2.tar.bz2   # Archive (can delete after extract)
├── nazario_phishing/
│   ├── *.eml                # ~4,000 phishing emails
│   └── ground_truth.csv     # Labels
├── enron/
│   ├── maildir/             # 500,000 emails in subdirs
│   ├── all/                 # Flat copy for evaluation
│   ├── ground_truth.csv     # Labels
│   └── enron_mail_20150507.tar.gz  # Archive (can delete)
└── test_dataset/            # Your synthetic test data
    ├── all/
    └── ground_truth.csv
```

### Disk Space Requirements

| Dataset | Compressed | Extracted | Total (with archive) |
|---------|-----------|-----------|---------------------|
| SpamAssassin | 50 MB | 80 MB | 130 MB |
| Nazario | 20 MB | 25 MB | 45 MB |
| TREC 2007 | 300 MB | 500 MB | 800 MB |
| Enron | 1.7 GB | 2.5 GB | 4.2 GB |

**Recommended:** 5-10 GB free space to be safe

---

## Next Steps After Download

### 1. Run Quick Test (100 emails)

```bash
python standalone_triage.py \
  --dataset data/spamassassin/spam_2 \
  --ground-truth data/spamassassin/ground_truth.csv \
  --max-emails 100 \
  --no-llm \
  --output results/quick_test.json
```

### 2. Analyze Misclassifications

```bash
# View false positives and false negatives
cat results/quick_test.json | python -m json.tool | grep -A 10 "misclassifications"
```

### 3. Tune System (if needed)

- If F1 < 80%: Enable LLM (`remove --no-llm`)
- If many false positives: Increase malicious threshold (75 → 80)
- If many false negatives: Decrease malicious threshold (75 → 70)

### 4. Run Full Evaluation

```bash
# All emails in dataset (no --max-emails limit)
python standalone_triage.py \
  --dataset data/spamassassin/spam_2 \
  --ground-truth data/spamassassin/ground_truth.csv \
  --no-llm \
  --output results/full_evaluation.json
```

### 5. Compare Configurations

```bash
# Rules-only
python standalone_triage.py --dataset data/spamassassin/spam_2 --ground-truth data/spamassassin/ground_truth.csv --no-llm --output results/rules_only.json

# With LLM
python standalone_triage.py --dataset data/spamassassin/spam_2 --ground-truth data/spamassassin/ground_truth.csv --max-emails 100 --output results/with_llm.json

# Compare F1 scores
echo "Rules-only F1:" && cat results/rules_only.json | python -m json.tool | grep f1_score
echo "With LLM F1:" && cat results/with_llm.json | python -m json.tool | grep f1_score
```

---

## Summary

### Quick Start Checklist

- [ ] Download SpamAssassin corpus (5 min)
- [ ] Extract files (1 min)
- [ ] Create ground truth (30 sec)
- [ ] Run evaluation on 100 emails (10 sec)
- [ ] Check F1 score (should be 85%+)
- [ ] Run full evaluation (2 min)
- [ ] (Optional) Enable LLM for accuracy boost

### Expected Timeline

| Task | Time | Status |
|------|------|--------|
| Download SpamAssassin | 2 min | ⏳ |
| Extract & setup | 2 min | ⏳ |
| Quick test (100 emails) | 10 sec | ⏳ |
| Full evaluation (1,400 emails) | 2 min | ⏳ |
| **Total** | **6-7 min** | ⏳ |

### Success Criteria

✅ F1 Score >= 85% (rules-only)
✅ F1 Score >= 90% (with LLM)
✅ Processing speed ~10 emails/sec (rules-only)
✅ No errors in evaluation

---

## Support

**Questions?** See `MASTER_GUIDE.md` Section 9 (Troubleshooting)
**Issues?** Check dataset file structure and ground truth format

🎯 **Ready to test on real phishing data!**

---

**Last Updated:** 2025-11-19
**Tested On:** macOS, Ubuntu 22.04
**Next:** See `MASTER_GUIDE.md` for full documentation
