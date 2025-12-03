# Changelog

All notable changes to VERIDEX will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2025-12-03

### Added
- ✅ **Comprehensive Unit Tests** (4 test modules, 30+ tests)
  - `test_auth_security.py`: Authentication, RBAC, JWT tokens
  - `test_ensemble_engine.py`: Ensemble verdict logic
  - `test_mdo_extractor.py`: HIPAA compliance validation
  - `test_metrics.py`: Performance metrics calculation
- ✅ **Secure Admin Setup Script** (`scripts/setup_admin.py`)
  - Auto-generates cryptographically secure passwords
  - Validates custom passwords against security policy
  - Prevents deployment with default credentials
- ✅ **Environment Configuration** (`.env.example`)
  - Template for secure configuration
  - JWT secret key management
  - Ollama settings
- ✅ **Security Documentation** (`SECURITY.md`)
  - Security features and policies
  - Deployment recommendations
  - Vulnerability reporting process
- ✅ **Assets Folder** (`assets/screenshots/`)
  - Structure for dashboard screenshots
  - Guidelines for visual documentation
- ✅ **MIT License** (required for open source)
- ✅ **Changelog** (this file)

### Changed
- 🔒 **SECURITY: Removed Default Password** (`changeme123`)
  - Admin credentials must now be created via setup script
  - Prevents accidental deployment with default credentials
  - Enhanced security posture for public release
- 🔒 **SECURITY: Removed Institution Identifiers**
  - Replaced CU Denver/Anschutz domains with generic examples
  - Maintains privacy for research environment
  - `config/config.yaml`: Generic internal domains
  - `src/core/*.py`: Example domains in code
- 📝 **Updated README**
  - Added Initial Setup section with setup script instructions
  - Fixed GitHub repository URLs (nessakodo/veridex)
  - Added reference to screenshot assets
  - Updated API authentication examples
  - Enhanced test documentation with coverage details
- 📝 **Updated Requirements**
  - Added `pytest-cov>=4.1.0` for coverage reports
- 🔐 **Updated .gitignore**
  - Added `data/users.yaml` (contains hashed passwords)
  - Added `.env` (contains secrets)
  - Configured to track screenshot assets
- 🔐 **Updated Security Documentation**
  - `docs/SECURITY_STATUS.md`: Reflects no-default-password policy
  - Password policy enforcement details

### Fixed
- 🐛 **HTML Template**: Removed pre-filled password in login form
- 🐛 **User Store**: Empty user store created instead of default admin
- 🐛 **Documentation**: Corrected placeholder GitHub username

### Security
- 🔒 **Zero Default Credentials**: Eliminates deployment with known passwords
- 🔒 **Secure Password Generation**: Cryptographically secure random passwords
- 🔒 **Privacy Protection**: No institution-specific PII in public code
- 🔒 **Test Coverage**: Validates security controls implementation

## [0.9.0] - 2025-12-02

### Added
- Initial research implementation
- Ensemble verdict engine (50% LLM + 50% Rules)
- HIPAA-compliant metadata-only processing
- FastAPI backend with JWT authentication
- RBAC (Admin, Analyst, Auditor roles)
- SHA-256 audit logging
- Dashboard UI
- SpamAssassin validation (91.74% F1, 100% precision)

---

## Version Classification

- **1.0.0**: Public release, production-ready for research/internal use
- **0.9.x**: Pre-release, research validation phase
- **Future (2.0.0+)**: Production PHI deployment (HTTPS, encryption, MFA)

---

**Note**: This project follows [Semantic Versioning](https://semver.org/):
- **MAJOR**: Incompatible API changes
- **MINOR**: Backwards-compatible functionality additions
- **PATCH**: Backwards-compatible bug fixes
