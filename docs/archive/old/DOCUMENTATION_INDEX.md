# Documentation Index

**Last Updated:** 2025-11-19
**System Version:** 2.0

---

## Quick Navigation

| I Want To... | Read This |
|--------------|-----------|
| **Understand the system** | [SYSTEM_ARCHITECTURE.md](#system-architecture) ⭐ |
| **Test the standalone tool** | [README.md](#readme) → Standalone section |
| **Deploy to production** | [ENTERPRISE_DEPLOYMENT_GUIDE.md](#enterprise-deployment-guide) ⭐ |
| **Use Defender data** | [ENTERPRISE_DEPLOYMENT_GUIDE.md](#enterprise-deployment-guide) → "Using Your Own Defender Data" |
| **Integrate with SIEM** | [ENTERPRISE_DEPLOYMENT_GUIDE.md](#enterprise-deployment-guide) → "SIEM Integration" |
| **Download public datasets** | [DATASET_DOWNLOAD_GUIDE.md](#dataset-download-guide) |
| **Understand verdicts** | [docs/VERDICT_TRANSPARENCY.md](#verdict-transparency) |
| **See validation results** | [IMPLEMENTATION_COMPLETE.md](#implementation-complete) |

---

## Core Documentation (ROOT)

### ⭐ SYSTEM_ARCHITECTURE.md
**Purpose:** Complete system overview and technical reference

**Contents:**
- Two operational modes (Dashboard vs Standalone)
- Architecture diagrams
- Component breakdown (all files and functions)
- Configuration files explained
- Testing procedures (both modes)
- Dataset integration
- Defender data import
- Enterprise integration points

**Who Should Read:** Everyone (start here!)

**Status:** ✅ Current (2025-11-19)

---

### ⭐ ENTERPRISE_DEPLOYMENT_GUIDE.md
**Purpose:** Production deployment for SOC teams

**Contents:**
- Deployment architecture options
- Using Defender data (manual + API)
- SIEM integration (Splunk, Sentinel)
- Docker & Kubernetes deployment
- Federal compliance (FISMA, HIPAA, FedRAMP)
- Performance tuning
- Monitoring & alerting
- SOC runbooks
- Cost analysis & ROI

**Who Should Read:** DevOps, SOC managers, compliance teams

**Status:** ✅ Current (2025-11-19)

---

### README.md
**Purpose:** Project overview and quick start

**Contents:**
- Simulation results
- Real-world validation (SpamAssassin 91.74% F1)
- Overview of ensemble approach
- Quick start (dashboard + standalone)
- Architecture summary
- Features list

**Who Should Read:** Everyone (initial overview)

**Status:** ✅ Updated with SpamAssassin results

---

### IMPLEMENTATION_COMPLETE.md
**Purpose:** Summary of completed implementation

**Contents:**
- Components built (1,465 lines of code)
- Test results (synthetic + SpamAssassin)
- Performance benchmarks (validated)
- Quick start commands
- Next steps roadmap
- Documentation reference table

**Who Should Read:** Stakeholders, researchers

**Status:** ✅ Updated with real validation data

---

### DATASET_DOWNLOAD_GUIDE.md
**Purpose:** How to get public phishing datasets

**Contents:**
- SpamAssassin (recommended first)
- Nazario phishing corpus
- Enron legitimate emails
- TREC 2007 spam
- PhishTank URLs
- Step-by-step download & evaluation instructions

**Who Should Read:** Researchers, validators

**Status:** ✅ Current

---

### MASTER_GUIDE.md
**Purpose:** Consolidated reference (all-in-one)

**Contents:**
- Everything from multiple docs combined
- Quick start
- Architecture
- Verdict logic
- Compliance
- Troubleshooting

**Who Should Read:** Optional (redundant with SYSTEM_ARCHITECTURE.md)

**Status:** ⚠️ REDUNDANT - Consider archiving

**Recommendation:** Archive to `docs/archive/` - use SYSTEM_ARCHITECTURE.md instead

---

### QUICKSTART_STANDALONE.md
**Purpose:** 30-minute standalone setup guide

**Contents:**
- Installation steps
- First evaluation
- Understanding results

**Who Should Read:** New users testing standalone mode

**Status:** ⚠️ REDUNDANT with README + SYSTEM_ARCHITECTURE

**Recommendation:** Archive to `docs/archive/` - content merged into SYSTEM_ARCHITECTURE.md

---

## Technical Documentation (docs/)

### docs/VERDICT_TRANSPARENCY.md
**Purpose:** Prove no generator bias in verdicts

**Contents:**
- Line-by-line code analysis
- Generator metadata exclusion proof
- Test cases verifying no bias
- Rule-based scoring breakdown

**Who Should Read:** Compliance officers, researchers

**Status:** ✅ Current

---

### docs/STANDALONE_IMPLEMENTATION.md
**Purpose:** Full standalone architecture deep-dive

**Contents:**
- Three-tier deployment model
- Complete code examples
- Federal compliance details
- All 16 rule indicators documented

**Who Should Read:** Developers implementing standalone mode

**Status:** ✅ Current

**Recommendation:** Keep for detailed reference

---

### docs/DATASET_INTEGRATION.md
**Purpose:** Architecture for public dataset testing

**Contents:**
- Dataset normalizer design
- Metrics calculator specs
- Target metrics (Precision >95%, Recall >85%)

**Who Should Read:** Researchers, developers

**Status:** ⚠️ PARTIALLY REDUNDANT with SYSTEM_ARCHITECTURE.md

**Recommendation:** Keep for detailed specifications, archive diagrams section

---

### docs/ABLATION_STUDY_FRAMEWORK.md
**Purpose:** Ensemble weight optimization framework

**Contents:**
- 10 preset configurations
- Ablation study runner design
- Systematic testing methodology

**Who Should Read:** Researchers tuning ensemble weights

**Status:** ✅ Current (future use)

---

### docs/ATTACHMENT_ANALYSIS.md
**Purpose:** Attachment verdict logic (currently Defender-dependent)

**Contents:**
- Current Defender dependency
- Future enhancements (YARA, Cuckoo, hash reputation)

**Who Should Read:** Developers adding attachment analysis

**Status:** ✅ Current (future roadmap)

---

### docs/THIRD_PARTY_INTEGRATIONS.md
**Purpose:** Threat intelligence API research

**Contents:**
- AlienVault OTX
- VirusTotal
- URLhaus
- PhishTank
- Integration designs
- Free tier strategies
- HIPAA compliance notes

**Who Should Read:** Developers adding threat intel

**Status:** ✅ Current (future roadmap)

---

### docs/RESEARCH_CONSIDERATIONS.md
**Purpose:** Research methodology notes

**Status:** ⚠️ REVIEW NEEDED - May be outdated

**Recommendation:** Review and archive if superseded by other docs

---

### docs/RESEARCH_AND_DEPLOYMENT.md
**Purpose:** Research + deployment notes

**Status:** ⚠️ REVIEW NEEDED - Likely redundant with ENTERPRISE_DEPLOYMENT_GUIDE.md

**Recommendation:** Review and archive if redundant

---

### docs/SECURITY_STATUS.md
**Purpose:** Security implementation status

**Status:** ⚠️ REVIEW NEEDED - Check if current

**Recommendation:** Merge into ENTERPRISE_DEPLOYMENT_GUIDE.md compliance section or archive

---

## Recommended Documentation Structure

### Keep in Root (Essential)
```
/
├── README.md                           # Project overview
├── SYSTEM_ARCHITECTURE.md ⭐           # Complete technical reference
├── ENTERPRISE_DEPLOYMENT_GUIDE.md ⭐   # Production deployment
├── IMPLEMENTATION_COMPLETE.md          # Summary of what's built
└── DATASET_DOWNLOAD_GUIDE.md           # How to get test data
```

### Keep in docs/ (Reference)
```
docs/
├── VERDICT_TRANSPARENCY.md             # Compliance proof
├── STANDALONE_IMPLEMENTATION.md        # Deep-dive standalone docs
├── THIRD_PARTY_INTEGRATIONS.md         # Threat intel APIs
├── ABLATION_STUDY_FRAMEWORK.md         # Ensemble tuning
└── ATTACHMENT_ANALYSIS.md              # Future roadmap
```

### Archive (Redundant)
```
docs/archive/
├── MASTER_GUIDE.md                     # Superseded by SYSTEM_ARCHITECTURE.md
├── QUICKSTART_STANDALONE.md            # Merged into SYSTEM_ARCHITECTURE.md
├── DATASET_INTEGRATION.md              # Partially redundant
├── RESEARCH_CONSIDERATIONS.md          # Review first
├── RESEARCH_AND_DEPLOYMENT.md          # Review first
└── SECURITY_STATUS.md                  # Review first
```

---

## File Organization Commands

```bash
# Create archive directory
mkdir -p docs/archive

# Archive redundant docs
mv MASTER_GUIDE.md docs/archive/
mv QUICKSTART_STANDALONE.md docs/archive/

# Review these before archiving
# - docs/RESEARCH_CONSIDERATIONS.md
# - docs/RESEARCH_AND_DEPLOYMENT.md
# - docs/SECURITY_STATUS.md
# - docs/DATASET_INTEGRATION.md (partial)

# Result: Clean root with 5 essential docs
# Root: README, SYSTEM_ARCHITECTURE, ENTERPRISE_DEPLOYMENT_GUIDE,
#       IMPLEMENTATION_COMPLETE, DATASET_DOWNLOAD_GUIDE
```

---

## Documentation Maintenance

### Update Frequency

| Document | Update When |
|----------|-------------|
| README.md | Major features added |
| SYSTEM_ARCHITECTURE.md | Code changes, new integrations |
| ENTERPRISE_DEPLOYMENT_GUIDE.md | Deployment changes, new integrations |
| IMPLEMENTATION_COMPLETE.md | Validation results change |
| DATASET_DOWNLOAD_GUIDE.md | New datasets added |
| docs/*.md | Feature-specific updates |

---

## Quick Reference Card

### Running the System

**Dashboard Mode:**
```bash
./start.sh
# Open http://localhost:8000/dashboard
# Login: admin / changeme123
```

**Standalone Evaluation:**
```bash
python standalone_triage.py \
  --dataset data/my_emails \
  --ground-truth data/labels.csv \
  --output results/eval.json
```

**Create Ground Truth:**
```bash
python scripts/create_ground_truth.py \
  --spam-dir data/spam \
  --ham-dir data/ham \
  --output data/ground_truth.csv
```

---

## Support

**Primary References:**
1. SYSTEM_ARCHITECTURE.md - Technical questions
2. ENTERPRISE_DEPLOYMENT_GUIDE.md - Deployment questions
3. DATASET_DOWNLOAD_GUIDE.md - Dataset questions

**Code Reference:**
- `src/datasets/email_parser.py` - Email parsing
- `src/core/standalone_ensemble_engine.py` - Standalone verdicts
- `src/core/ensemble_verdict_engine.py` - Dashboard verdicts
- `src/evaluation/metrics_calculator.py` - Metrics
- `standalone_triage.py` - CLI evaluation tool

---

**Version:** 1.0
**Maintained By:** Project team
**Last Cleanup:** 2025-11-19
