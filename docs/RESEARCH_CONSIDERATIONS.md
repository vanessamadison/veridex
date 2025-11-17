# Phase 2 Research Considerations

## Overview

This document preserves research directions and considerations from the Phase 2 Build Plan that support the academic and practical foundation of the Email Triage Automation System.

---

## Research Question

**How can local LLM-powered automation reduce SOC analyst workload while maintaining HIPAA compliance and achieving >70% automation rate for email triage decisions?**

### Sub-Questions:
1. What ensemble approach (LLM + Rules + Defender signals) yields optimal accuracy?
2. How does BCL threshold tuning affect false positive/negative rates?
3. What confidence threshold minimizes analyst review while ensuring safety?
4. How do simulated emails compare to real Microsoft Defender data?

---

## Key Metrics for Research

### Automation Performance
- **Automation Rate**: Target >70% (achieved 68% in simulation)
- **False Positive Rate**: Target <5%
- **False Negative Rate**: Target <2%
- **Average Processing Time**: Target <3 seconds (achieved 0.3s)

### Analyst Efficiency
- **Time Saved**: Measure pre/post automation analyst hours
- **Queue Depth**: Monitor backlog reduction
- **Review Quality**: Track analyst override frequency
- **Cognitive Load**: Survey analyst satisfaction

### System Accuracy
- **Precision**: True positives / (True positives + False positives)
- **Recall**: True positives / (True positives + False negatives)
- **F1 Score**: Harmonic mean of precision and recall
- **ROC-AUC**: Overall classifier performance

---

## Ensemble Verdict Engine Research

### Current Weights
```
Ollama LLM:      40%
Rule-Based:      30%
Defender Signals: 30%
```

### Research Experiments

1. **Weight Optimization**
   - Test different weight combinations
   - Measure accuracy at each configuration
   - Document: `results/weight_experiments/`

2. **Confidence Threshold Tuning**
   - Current: 75% for auto-resolution
   - Test range: 60% to 90%
   - Measure: false positive/negative impact

3. **BCL Threshold Impact**
   - Current: BCL >= 7 triggers auto-bulk
   - Test: BCL 5, 6, 7, 8, 9
   - Compare to Microsoft Defender defaults:
     - Default policy: 7
     - Standard preset: 6
     - Strict preset: 5

4. **Rule-Based Logic Evolution**
   - Document analyst SOP patterns
   - Encode as rules
   - Measure rule hit rate
   - Track rule accuracy over time

---

## Data Comparison Research

### Simulation vs. Real Data

Export and compare these fields:

| Field | Simulation | Real Defender | Match Quality |
|-------|-----------|---------------|---------------|
| Subject patterns | 20 templates | Real submissions | High |
| Sender domains | 15 domains (legit/suspicious/bulk) | Actual domains | Medium |
| BCL distribution | 0-9 (weighted) | Actual BCL scores | High |
| SPF/DKIM/DMARC | Pass/Fail/None | Actual auth results | High |
| URL count | 0-3 per email | Real URL counts | Medium |
| Attachment types | .exe, .pdf, .docx, etc. | Actual file types | High |
| Threat types | Phishing, Bulk, None | Defender classifications | High |

### Recommended Analysis

1. **Distribution Comparison**
   ```python
   # Compare BCL distributions
   sim_bcl = exported_simulation['BCL'].value_counts()
   real_bcl = defender_export['Bulk complaint level'].value_counts()
   # Calculate KL divergence or chi-square test
   ```

2. **Subject Line Analysis**
   - Extract keywords from real subjects
   - Compare to simulation templates
   - Add missing patterns to generator

3. **Domain Reputation**
   - Map real suspicious domains to simulation
   - Include typosquatting patterns
   - Add more legitimate domain variations

4. **Authentication Failure Patterns**
   - Analyze SPF/DKIM/DMARC failures in real data
   - Correlate with threat outcomes
   - Adjust simulation probabilities

---

## Detection Technology Research

### Microsoft Defender Detection Technologies

From the Email Entity Page documentation:

1. **Advanced filter** - Machine learning signals
2. **Campaign** - Part of coordinated attack
3. **File detonation** - Safe Attachments scanning
4. **File reputation** - Known malicious files
5. **Fingerprint matching** - Similar to previous threats
6. **Impersonation** - Brand/domain/user spoofing
7. **LLM content analysis** - Large language model detection
8. **Mail bombing** - DDoS via email
9. **Mixed analysis** - Multiple indicators
10. **Spoof detection** - DMARC/intra-org/external
11. **URL detonation** - Safe Links scanning

### Research Opportunities

- Map each detection technology to rule-based logic
- Measure which technologies trigger most often
- Build detection coverage matrix
- Identify gaps in current automation

---

## HIPAA Research Considerations

### Data Minimization Study

Research question: **What is the minimum metadata required for accurate verdict prediction?**

Test by progressively removing fields:
1. Full feature set (all metadata)
2. Remove sender IP
3. Remove exact timestamps
4. Remove URL details
5. Measure accuracy degradation at each step

**Goal**: Minimize data exposure while maintaining accuracy

### Audit Log Analysis

Research question: **Can audit logs detect policy violations?**

Analyze patterns:
- Unusual access times
- High-volume data exports
- Role escalation attempts
- Authentication failures

### Anonymization Research

Document anonymization techniques for:
- Email addresses (hash or replace)
- Domain names (keep TLD only)
- IP addresses (subnet masking)
- Subject lines (keyword extraction only)

---

## Ollama LLM Research

### Model Comparison

Test different Ollama models:

| Model | Size | Speed | Accuracy | HIPAA Safe |
|-------|------|-------|----------|------------|
| mistral:latest | 7B | Fast | High | Yes (local) |
| llama3:latest | 8B | Medium | Higher | Yes (local) |
| codellama:latest | 7B | Fast | Medium | Yes (local) |
| phi3:latest | 3.8B | Fastest | Medium | Yes (local) |

### Prompt Engineering

Research optimal prompts:

1. **Zero-shot**: Direct classification
2. **Few-shot**: Examples in prompt
3. **Chain-of-thought**: Step-by-step reasoning
4. **Role-based**: "You are a SOC analyst..."

Document prompt performance in `results/prompt_experiments/`

### Temperature Tuning

- Current: 0.1 (conservative)
- Test: 0.0, 0.1, 0.3, 0.5, 0.7
- Measure: Consistency vs. accuracy trade-off

---

## SOC Workflow Research

### Analyst Interview Questions

1. What emails take longest to triage?
2. What patterns indicate phishing immediately?
3. What makes you uncertain about a verdict?
4. How do you prioritize your queue?
5. What information do you wish Defender provided?

### Workflow Optimization

Study current process:
1. Email arrives in queue
2. Analyst reviews metadata
3. Analyst checks authentication
4. Analyst examines URLs/attachments
5. Analyst makes verdict
6. Analyst documents decision

Measure time at each step, automate bottlenecks.

### Cognitive Load Reduction

Research question: **Does automation reduce analyst cognitive fatigue?**

Metrics:
- Errors per hour (before/after automation)
- Consistency of decisions
- Job satisfaction surveys
- Queue clearance time

---

## Future Research Directions

### 1. Graph Neural Networks for Email Campaigns

- Model email relationships as graphs
- Detect coordinated phishing campaigns
- Link related incidents automatically

### 2. Federated Learning

- Train models across multiple organizations
- Share threat intelligence without sharing data
- Maintain HIPAA compliance through federation

### 3. Explainable AI

- Add reasoning explanations to verdicts
- Show which features influenced decision
- Build analyst trust in automation

### 4. Active Learning

- Analyst feedback improves model
- Prioritize uncertain cases for review
- Continuous model improvement

### 5. Time-Series Analysis

- Detect seasonal phishing patterns
- Predict high-volume attack periods
- Proactive resource allocation

---

## Data Collection Protocol

### What to Log for Research

1. **Every Verdict**
   - Timestamp
   - Email features
   - Ensemble scores (LLM, rules, Defender)
   - Final verdict
   - Confidence level

2. **Analyst Overrides**
   - Original auto-verdict
   - Analyst verdict
   - Reason for override
   - Time spent

3. **System Performance**
   - Processing time
   - Queue depth
   - Automation rate
   - Error rate

### Storage

```
results/
├── research/
│   ├── verdicts/           # All automated verdicts
│   ├── overrides/          # Analyst corrections
│   ├── experiments/        # Weight/threshold tests
│   └── comparisons/        # Simulation vs. real data
```

---

## Publication Considerations

### Potential Venues

- **IEEE S&P**: Security and Privacy
- **USENIX Security**: Systems security
- **ACM CCS**: Computer and Communications Security
- **NDSS**: Network and Distributed System Security
- **JAMIA**: Journal of American Medical Informatics

### Key Contributions

1. HIPAA-compliant local LLM for SOC automation
2. Ensemble approach combining AI + rules + threat intel
3. BCL-aware bulk email classification
4. Quantified analyst workload reduction
5. Metadata-only processing framework

### Ethical Considerations

- No real PHI in publications
- Anonymize all data examples
- Get IRB approval if studying real emails
- Disclose limitations of simulation
- Address potential for automation bias

---

## Conclusion

This research framework supports both academic publication and practical deployment. The key insight is that local LLM processing (Ollama) combined with established SOC rules and Microsoft Defender signals can achieve substantial automation while maintaining HIPAA compliance.

The 68% automation rate achieved in simulation validates the approach, though production deployment will require additional validation against real-world data with appropriate institutional approvals.

---

**Document Version:** 1.0
**Last Updated:** 2025-11-16
**Research Lead:** SOC Automation Team
