# Security Policy

## Supported Versions

| Version | Support Status |
|:---|:---|
| 1.0.x | Supported (Current - Research Phase) |
| < 1.0 | Not supported |

## Current Maturity

This project is in a **research and internal testing phase**. It is not hardened for production use with sensitive communications or PHI. The security controls described below are implemented for the research prototype and would require significant additional work before any production deployment.

## Security Features

### Authentication & Authorization
- **JWT Token Authentication**: Secure session management with HS256 encryption
- **Role-Based Access Control (RBAC)**: Admin, Analyst, Auditor roles
- **Password Policies**: 12+ character minimum, complexity requirements
- **Account Lockout**: 5 failed attempts triggers 30-minute lockout
- **No Default Credentials**: Admin password must be set via setup script

### Metadata-Only Processing
- **No access to email body content**: Only headers and authentication results processed
- **Minimum Necessary Standard**: Design follows 45 CFR 164.502(b) principles
- **Local LLM Processing**: No cloud-based content analysis
- **Audit Logging**: SHA-256 hash-chained tamper detection

### Data Protection
- **Password Hashing**: SHA-256 with salt
- **Export Rate Limiting**: 10 exports per hour per user
- **Audit Trail**: All authentication events and decisions logged
- **Session Management**: 30-minute access token, 7-day refresh token

## Deployment Recommendations

### Research/Internal Use (Current)
This prototype is suitable for:
- Academic research environments
- Internal testing and validation
- Proof-of-concept deployments
- Analysis of non-sensitive, simulated, or public email data

### Production Deployment (Not Yet Implemented)
The following would be required before any use involving sensitive communications or PHI:
- HTTPS/TLS encryption (currently HTTP-only for local dev)
- Database encryption at rest
- Multi-factor authentication (MFA)
- Secure key management (HSM or cloud KMS)
- Network segmentation and firewall rules
- Regular security audits and penetration testing
- HIPAA Business Associate Agreement (BAA) compliance
- Formal risk assessment
- Incident response plan
- Breach notification procedures
- Backup and disaster recovery

## Initial Setup Security

### First-Time Installation

1. **Run Setup Script** (Required)
   ```bash
   python3 scripts/setup_admin.py
   ```
   - Generates secure admin password automatically (recommended)
   - OR allows custom password with strength validation
   - Creates user store (not committed to version control)

2. **Secure the Password**
   - Store in password manager
   - Never commit to version control
   - Rotate regularly

3. **Environment Variables**
   - Copy `.env.example` to `.env`
   - Set `JWT_SECRET_KEY` (auto-generated if not provided)
   - Never commit `.env` to git

## Reporting Security Issues

**DO NOT** create public GitHub issues for security vulnerabilities.

Instead:
1. Email security concerns to: security@illapex.com
2. Include:
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact assessment
   - Suggested fix (if applicable)

## Security Best Practices

### For Developers
- Never hardcode credentials or secrets
- Use environment variables for sensitive configuration
- Run tests before committing: `pytest tests/ -v`
- Review OWASP Top 10 before adding features
- Keep dependencies up to date: `pip list --outdated`

### For Operators
- Change default admin password immediately after setup
- Enable audit logging: `config.yaml` -> `log_all_decisions: true`
- Monitor `auth_audit.json` for suspicious activity
- Restrict network access to internal IPs only

### For Researchers
- Use test datasets without real PHI
- Document any modifications to security controls
- Report findings responsibly

## Compliance Notes (Research Phase)

The following standards informed the design of this prototype. Checkmarks indicate design alignment, not formal certification or audit:

### HIPAA-Aligned Design Principles
- 45 CFR 164.502(b): Minimum Necessary Standard (metadata-only approach)
- 45 CFR 164.306: Security Standards - General Rules (access controls implemented)
- 45 CFR 164.312(a)(1): Access Control (RBAC, JWT)
- 45 CFR 164.312(d): Person or Entity Authentication (password policies)
- 45 CFR 164.312(a)(2)(iv): Encryption (not yet implemented; required for production)

### NIST Cybersecurity Framework Alignment
- ID.AM: Asset Management (data inventory)
- PR.AC: Access Control (RBAC, JWT)
- PR.DS: Data Security (metadata-only processing)
- DE.CM: Continuous Monitoring (audit logging)
- PR.DS-1: Encryption at rest (not yet implemented; required for production)

## Security Audit Log

| Date | Version | Change | Impact |
|:---|:---|:---|:---|
| 2025-12-03 | 1.0.0 | Removed default credentials | Eliminates default password risk |
| 2025-12-03 | 1.0.0 | Added setup script | Enforces secure password on install |
| 2025-12-03 | 1.0.0 | Removed institution identifiers | Genericizes for public release |
| 2025-12-03 | 1.0.0 | Added comprehensive unit tests | Validates security controls |
| 2026-03-16 | 1.0.0 | Removed committed user store from history | Eliminates credential exposure in git |

---

**Last Updated**: March 16, 2026
**Security Contact**: security@illapex.com
**Version**: 1.0.0 (Research Phase)
