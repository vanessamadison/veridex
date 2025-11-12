# Data Handling Policy

All datasets in this repository are fully **de-identified** and **HIPAA-compliant**.  
They were generated or sanitized using metadata-only exports (headers, BCL scores, SPF/DKIM/DMARC results)  
without any Protected Health Information (PHI).

### Validation:
- Confirmed absence of PHI via `code/hipaa_validator.py`
- Fields reviewed: Subject (truncated), Sender (domain-only), Timestamps, BCL, SPF, DKIM, DMARC
- No patient identifiers, clinical notes, or attachment names retained

For reproducibility, raw datasets are excluded. Any real-world data use must follow:
- IRB approval
- Secure access control (least privilege)
- Encryption at rest and in transit
