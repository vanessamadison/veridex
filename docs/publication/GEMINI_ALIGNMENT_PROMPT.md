# 🤖 Gemini Alignment Prompt for VERIDEX

## **Copy-Paste Prompt for Gemini**

Use this prompt to have Gemini help align your VERIDEX application with your research paper:

---

```
I'm preparing VERIDEX, a HIPAA-compliant phishing triage system, for academic
publication. I need you to help ensure the codebase is perfectly aligned with
the research paper findings.

PROJECT OVERVIEW:
=================
**Name**: VERIDEX (Verification Intelligence for Rapid Email Defense)
**Purpose**: Automated phishing email triage for healthcare environments
**Key Requirement**: HIPAA-compliant (metadata-only, no PHI access)

VALIDATED PERFORMANCE METRICS:
===============================
- F1 Score: 91.74%
- Precision: 100.00% (ZERO false positives - critical!)
- Recall: 84.74%
- Accuracy: 84.74%
- Processing Time: 0.3s per email (with LLM)
- Automation Rate: 68%
- Test Corpus: SpamAssassin Spam_2 (N=1,396)

TECHNICAL ARCHITECTURE:
=======================
- **Ensemble Approach**: 50% Rules-Based + 50% Local Ollama LLM
- **Confidence Threshold**: 75% for auto-resolution
- **Routing**: <75% confidence → Analyst review queue
- **Authentication Factors**: SPF, DKIM, DMARC with weighted scoring
- **BCL Analysis**: Bulk Complaint Level (0-9 scale)
- **Threat Analysis**: URL scanning, attachment analysis, Defender signals

KEY FEATURES TO PRESERVE:
=========================
1. **Decision Factors Analysis** - Transparent XAI interface showing:
   - Color-coded factors (green=positive, red=negative, yellow=neutral)
   - Impact weights for each factor (+15, -30, etc.)
   - Clear explanation of verdict reasoning

2. **HIPAA Compliance** - Metadata-only processing:
   - NO access to email body content
   - NO access to full subject lines
   - NO access to attachment contents
   - Only headers, authentication, and Defender signals

3. **Dashboard Features**:
   - Real-time triage queue
   - Bulk actions for analysts
   - Incident ID assignment
   - Audit logging with SHA-256 hash chain
   - JWT authentication with RBAC
   - Export rate limiting

RESEARCH PAPER ALIGNMENT NEEDS:
================================

Please help me with the following tasks:

1. **Code Review**: Review the codebase and identify any discrepancies between
   the code and the paper's claims about:
   - Performance metrics
   - Architecture design
   - HIPAA compliance measures
   - Decision factor calculation
   - Confidence threshold implementation

2. **Feature Validation**: Verify that these paper claims are implemented:
   - 50/50 ensemble weighting (Rules + LLM)
   - 75% confidence threshold for auto-resolution
   - Zero false positive requirement
   - Metadata-only approach (no PHI access)
   - Decision factors analysis with weighted impacts
   - Color-coded factor visualization

3. **Documentation Alignment**: Check if code comments and documentation
   accurately reflect:
   - The validated metrics (91.74% F1, 100% precision, etc.)
   - The ensemble methodology
   - The clinical workflow protection (zero FPR requirement)
   - The HIPAA compliance approach

4. **Missing Features**: Identify any features mentioned in the paper that
   might not be fully implemented in the code

5. **Suggested Improvements**: Recommend code enhancements that would:
   - Better demonstrate the paper's contributions
   - Improve reproducibility for other researchers
   - Strengthen HIPAA compliance documentation
   - Enhance the explainable AI (XAI) interface

6. **Testing Recommendations**: Suggest additional tests or validations to
   ensure the code performs exactly as described in the paper

CODEBASE STRUCTURE:
===================
/src/
  /api/ - FastAPI backend with JWT auth
  /auth/ - RBAC and security
  /core/ - Ensemble engine, verdict logic
  /datasets/ - Email parsing
  /evaluation/ - Metrics calculation
  /frontend/ - Dashboard UI (VERIDEX branding)
  /generators/ - Test data generation

/config/ - Configuration files
/scripts/ - Testing and validation scripts
/docs/figures/ - Publication figures

SPECIFIC QUESTIONS:
===================
1. Does the confidence threshold calculation match the paper's description?
2. Are the decision factor weights accurately implemented?
3. Is the HIPAA compliance properly enforced in all code paths?
4. Does the error handling preserve the zero false positive requirement?
5. Are there any security vulnerabilities that could impact claims?

OUTPUT FORMAT:
==============
Please provide:
1. Executive summary of alignment status
2. Detailed findings by category
3. Specific code locations that need updates
4. Recommended changes with code examples
5. Testing recommendations
6. Publication readiness assessment

CONTEXT FILES:
==============
I will provide you with:
- Research paper abstract and key sections
- Core codebase files (main.py, ensemble engine, UI)
- Configuration files
- Testing results

Please be thorough and critical - this is for academic publication, so accuracy
is paramount. Point out any exaggerations, inconsistencies, or implementation
gaps that could undermine the research credibility.
```

---

## 📂 **Files to Provide to Gemini**

### **Round 1: Overview**
1. FINAL_VALIDATION_REPORT.md
2. VERIDEX_UI_ENHANCEMENTS.md
3. Paper Executive Summary + Section 4.1 + Section 5.3

### **Round 2: Core Code**
1. `src/api/main.py` (API endpoints)
2. `src/core/ensemble_verdict_engine.py` (verdict logic)
3. `src/frontend/templates/index.html` (UI with decision factors)
4. `config/config.yaml` (configuration)

### **Round 3: Validation**
1. `standalone_triage.py` (testing script)
2. `results/validation_*/spamassassin_spam2.json` (test results)
3. `scripts/generate_figures.py` (figure generation)

---

## 🎯 **Follow-Up Prompts**

After Gemini's initial response, use these follow-ups:

### For Code Fixes:
```
For each issue you identified, please provide:
1. Exact file path and line numbers
2. Current code (what's wrong)
3. Corrected code (what it should be)
4. Explanation of why the change is needed
5. How it affects the paper's claims
```

### For Testing:
```
Based on the paper's claims of 91.74% F1 and 100% precision, what specific
unit tests should I add to ensure these metrics are reproducible? Provide
test code examples using pytest.
```

### For Documentation:
```
Review all code comments and docstrings. Flag any that:
1. Contradict the paper's methodology
2. Use outdated terminology (pre-VERIDEX branding)
3. Reference incorrect metrics
4. Don't match the actual implementation
```

### For HIPAA Compliance:
```
Act as a HIPAA compliance auditor. Review the code and identify any paths
where PHI could potentially be accessed, logged, or exposed. For each path:
1. Describe the risk
2. Show the vulnerable code
3. Provide secure alternative
4. Cite relevant HIPAA requirement (45 CFR 164.xxx)
```

### For Publication Readiness:
```
I'm submitting to JAMIA (Journal of the American Medical Informatics Association).
Review the codebase and paper alignment for:
1. Reproducibility: Can other researchers replicate the results?
2. Transparency: Are methods clearly documented in code?
3. Rigor: Any shortcuts or assumptions that could be criticized?
4. Impact: Code features that demonstrate healthcare value
```

---

## 🔄 **Iterative Alignment Process**

### Step 1: Initial Assessment (Gemini)
- Paste the main prompt above
- Attach FINAL_VALIDATION_REPORT.md
- Attach paper sections 4.1 and 5.3
- Get overview of alignment status

### Step 2: Code Review (Gemini)
- Share main codebase files
- Get specific fix recommendations
- Identify missing features

### Step 3: Implementation (You)
- Apply recommended fixes
- Add missing features
- Update documentation

### Step 4: Verification (Gemini)
- Share updated code
- Confirm fixes address issues
- Get final publication readiness assessment

### Step 5: Testing (You + Gemini)
- Run all tests
- Share results with Gemini
- Confirm metrics still match paper

---

## 📊 **Expected Gemini Output Structure**

```
ALIGNMENT ASSESSMENT: VERIDEX
=============================

EXECUTIVE SUMMARY:
Overall Alignment: 85% ✅
Critical Issues: 2 🔴
Moderate Issues: 5 🟡
Minor Issues: 8 🟢

CRITICAL ISSUES (Must Fix):
---------------------------
1. [FILE: src/core/ensemble_engine.py:145]
   ISSUE: Confidence threshold hardcoded as 0.70, paper claims 0.75
   IMPACT: Affects automation rate calculations
   FIX: Change line 145 to: if confidence >= 0.75:

2. [FILE: src/frontend/templates/index.html:1210]
   ISSUE: BCL weight showing -35, paper claims -40 for high BCL
   IMPACT: Decision factors display inconsistent with methodology
   FIX: Update BCL weight calculation...

[Continue for all issues...]

TESTING RECOMMENDATIONS:
------------------------
1. Add unit test for 75% confidence threshold
2. Add integration test for zero FPR requirement
3. Add validation test for metadata-only enforcement

PUBLICATION READINESS:
---------------------
Current Status: 85% ready
After Fixes: 98% ready
Confidence: HIGH ✅

The codebase substantially matches the paper claims. After fixing the
critical issues, the project will be publication-ready.
```

---

## 💡 **Tips for Using Gemini**

1. **Be Specific**: Provide exact paper sections and code files
2. **Iterate**: Don't expect perfection in one pass
3. **Cross-Check**: Verify Gemini's recommendations against paper
4. **Document Changes**: Keep track of what you fix based on feedback
5. **Final Review**: Run all tests after implementing Gemini's suggestions

---

## ✅ **Success Criteria**

Your codebase is publication-aligned when:
- ✅ All metrics match paper claims exactly
- ✅ Architecture implementation matches paper description
- ✅ No HIPAA compliance gaps
- ✅ Documentation reflects validated methodology
- ✅ Tests confirm reproducible results
- ✅ No contradictions between code and paper

---

**Ready to Use**: Copy the main prompt above and paste into Gemini!
**Expected Time**: 2-3 hours for full alignment process
**Outcome**: Publication-ready, paper-aligned codebase
