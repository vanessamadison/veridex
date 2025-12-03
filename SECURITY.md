# Security Policy

## Supported Versions

| Version | Support Status |
|:---|:---|
| 1.0.x | ✅ Supported (Current) |
| < 1.0 | ❌ Not supported |

## Security Features

### Authentication & Authorization
- **JWT Token Authentication**: Secure session management with HS256 encryption
- **Role-Based Access Control (RBAC)**: Admin, Analyst, Auditor roles
- **Password Policies**: 12+ character minimum, complexity requirements
- **Account Lockout**: 5 failed attempts triggers 30-minute lockout
- **No Default Credentials**: Admin password must be set via setup script

### HIPAA Compliance
- **Metadata-Only Processing**: No access to email body content
- **Minimum Necessary Standard**: Adheres to 45 CFR 164.502(b)
- **Zero PHI Exposure**: Only headers and authentication results processed
- **Local LLM Processing**: No cloud-based content analysis
- **Audit Logging**: SHA-256 hash-chained tamper detection

### Data Protection
- **Password Hashing**: SHA-256 with salt
- **Export Rate Limiting**: 10 exports per hour per user
- **Audit Trail**: All authentication events and decisions logged
- **Session Management**: 30-minute access token, 7-day refresh token

## Deployment Recommendations

### Research/Internal Deployment (Current)
✅ **Ready for:**
- Academic research environments
- Internal testing and validation
- Proof-of-concept deployments
- Non-PHI email analysis

### Production Deployment (Phase 2 Required)
⚠️ **Additional requirements for PHI/Production:**
- HTTPS/TLS encryption (currently HTTP-only for local dev)
- Database encryption at rest
- Multi-factor authentication (MFA)
- Secure key management (HSM or cloud KMS)
- Network segmentation and firewall rules
- Regular security audits and penetration testing
- HIPAA Business Associate Agreement (BAA) compliance

## Initial Setup Security

### First-Time Installation

1. **Run Setup Script** (Required)
   ```bash
   python3 scripts/setup_admin.py
   ```
   - Generates secure admin password automatically (recommended)
   - OR allows custom password with strength validation
   - Creates encrypted user store

2. **Secure the Password**
   - Store in password manager (1Password, LastPass, etc.)
   - Never commit to version control
   - Rotate every 90 days for production

3. **Environment Variables**
   - Copy `.env.example` to `.env`
   - Set `JWT_SECRET_KEY` (auto-generated if not provided)
   - Never commit `.env` to git

## Reporting Security Issues

**DO NOT** create public GitHub issues for security vulnerabilities.

Instead:
1. Email security concerns to: [Your Security Email]
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
- Enable audit logging: `config.yaml` → `log_all_decisions: true`
- Monitor `auth_audit.json` for suspicious activity
- Restrict network access to internal IPs only
- Regular password rotation (90-day policy enforced)

### For Researchers
- Use test datasets without real PHI
- Document any modifications to security controls
- Report findings responsibly
- Cite security design decisions in publications

## Compliance Statements

### HIPAA Compliance (Research Phase)
- ✅ 45 CFR 164.502(b): Minimum Necessary Standard
- ✅ 45 CFR 164.306: Security Standards - General Rules
- ✅ 45 CFR 164.312(a)(1): Access Control
- ✅ 45 CFR 164.312(d): Person or Entity Authentication
- ⚠️ 45 CFR 164.312(a)(2)(iv): Encryption required for production

### NIST Cybersecurity Framework
- ✅ ID.AM: Asset Management (data inventory)
- ✅ PR.AC: Access Control (RBAC, JWT)
- ✅ PR.DS: Data Security (metadata-only)
- ✅ DE.CM: Continuous Monitoring (audit logging)
- ⚠️ PR.DS-1: Encryption at rest (Phase 2)

## Security Audit Log

| Date | Version | Change | Impact |
|:---|:---|:---|:---|
| 2025-12-03 | 1.0.0 | Removed default credentials | ✅ Eliminates default password risk |
| 2025-12-03 | 1.0.0 | Added setup script | ✅ Enforces secure password on install |
| 2025-12-03 | 1.0.0 | Removed institution identifiers | ✅ Genericizes for public release |
| 2025-12-03 | 1.0.0 | Added comprehensive unit tests | ✅ Validates security controls |

---

**Last Updated**: December 3, 2025
**Security Contact**: [Your Contact]
**Version**: 1.0.0
