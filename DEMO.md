# VERIDEX Demo Script

This document provides a step-by-step guide to demonstrate the core capabilities of the VERIDEX phishing detection engine. We will use the `standalone_triage.py` script to analyze a small sample of emails and review the results.

This approach focuses on the core analysis engine for a quick and powerful demonstration.

---

## 1. Prerequisites

Before running the demo, ensure the following are installed:

*   **Python 3.9+**
*   **Ollama:** Follow the installation guide at [ollama.ai](https://ollama.ai).

---

## 2. Setup

First, set up the project environment.

### a. Install Dependencies

This command installs all the necessary Python libraries.

```bash
pip install -r requirements.txt
```

### b. Download the LLM Model

VERIDEX uses a local `mistral` model for metadata-first analysis without cloud exposure. This command downloads the model.

```bash
ollama pull mistral
```

---

## 3. Demo Execution: Core Engine Triage

We will run the standalone triage script on a small sample of 10 emails from the SpamAssassin dataset included in the project.

### a. Run Analysis with the Ensemble Engine (LLM + Rules)

This command runs the full analysis, combining rule-based logic with LLM insights.

```bash
python3 standalone_triage.py \
    --dataset data/spamassassin/spam_2 \
    --ground-truth data/spamassassin/ground_truth.csv \
    --limit 10 \
    --output results/demo_run_ensemble.json
```
This will generate a file at `results/demo_run_ensemble.json`.

### b. Examine the Results

You can now view the JSON output to see the verdict for each email. The results will look similar to this snippet, which shows one legitimate email (`ham`) and one phishing email (`spam`):

```json
[
  {
    "email_id": "00001.7c53336b37003a9286aba55d2945844c",
    "ground_truth": "ham",
    "verdict": "Legitimate",
    "confidence": 95,
    "is_correct": true,
    "explanation": "Predicted as Legitimate with 95% confidence. Justification: Email is legitimate. Final verdict confidence updated to 95 based on LLM analysis."
  },
  {
    "email_id": "00001.317e78fa8ee2f54cd4890fdc09ba8176",
    "ground_truth": "spam",
    "verdict": "Phishing",
    "confidence": 99,
    "is_correct": true,
    "explanation": "Predicted as Phishing with 99% confidence. Justification: The email content and structure exhibit strong indicators of a phishing attempt. Final verdict confidence updated to 99 based on LLM analysis."
  }
]
```

**Key fields to note:**
*   `"verdict"`: The final classification (e.g., "Legitimate", "Phishing").
*   `"confidence"`: The model's confidence in its verdict (0-100).
*   `"is_correct"`: A validation field that checks the verdict against the `ground_truth`.
*   `"explanation"`: The reasoning provided by the AI.

---

## 4. Demo Execution: Rules-Only Engine

VERIDEX can run in a faster, "rules-only" mode. This demonstrates the system's flexibility for different operational needs.

### a. Run Analysis (Rules-Only)

The `--no-llm` flag disables the local language model.

```bash
python3 standalone_triage.py \
    --dataset data/spamassassin/spam_2 \
    --ground-truth data/spamassassin/ground_truth.csv \
    --limit 10 \
    --no-llm \
    --output results/demo_run_rules_only.json
```
This will generate a file at `results/demo_run_rules_only.json`. You can inspect this file to see the difference in output and reasoning.

---

## 5. Next Steps and Full Validation

This concludes the basic demo. To perform a comprehensive evaluation of the system's performance, you can run the full validation script.

### Run Comprehensive Validation

This script tests the engine against all included datasets and generates detailed performance reports in the `results/dataset_validation/` directory.

```bash
bash scripts/validate_all_datasets.sh
```

This provides a full picture of the system's accuracy, precision, and recall, as highlighted in the `README.md`.

```
