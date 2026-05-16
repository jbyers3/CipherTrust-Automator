# CipherTrust Automator

> Python automation framework for Thales CipherTrust Manager — key lifecycle management, policy synchronization, and compliance audit reporting via REST API.

![Python](https://img.shields.io/badge/Python-3.9+-blue?logo=python)
![License](https://img.shields.io/badge/License-MIT-green)
![Status](https://img.shields.io/badge/Status-Active-brightgreen)

---

## Overview

Managing CipherTrust at scale manually is error-prone and audit-unfriendly. This toolkit automates the repetitive, high-stakes tasks:

- **Key Rotation** — Schedule and enforce key lifecycle policies across environments
- **Policy Sync** — Push encryption policies from version-controlled YAML to CipherTrust
- **Audit Reports** — Generate SOX/PCI-DSS compliant reports with cryptographic evidence
- **Connection Management** — Reusable authenticated session handler with token refresh

Built for SRE/security engineering teams operating CipherTrust in enterprise environments.

---

## Project Structure

```
ciphertrust-automator/
├── scripts/
│   ├── cipher_connect.py     # Authenticated session manager
│   ├── key_rotation.py       # Key lifecycle automation
│   ├── policy_sync.py        # Policy-as-code sync engine
│   ├── audit_report.py       # Compliance report generator
│   └── utils.py              # Shared helpers and logging
├── config/
│   ├── config.yaml.example   # Environment configuration template
│   └── logging.yaml          # Logging configuration
├── docs/
│   ├── SETUP.md              # Detailed setup guide
│   └── API_REFERENCE.md      # CipherTrust API reference notes
├── tests/
│   ├── test_cipher_connect.py
│   └── test_key_rotation.py
├── logs/                     # Runtime logs (gitignored)
├── requirements.txt
└── setup.py
```

---

## Quick Start

### Prerequisites
- Python 3.9+
- CipherTrust Manager instance (on-prem or cloud)
- API credentials with appropriate permissions

### Installation

```bash
git clone https://github.com/YOUR_USERNAME/ciphertrust-automator.git
cd ciphertrust-automator
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### Configure

```bash
cp config/config.yaml.example config/config.yaml
# Edit config/config.yaml with your CipherTrust host and credentials
```

### Run Key Rotation

```bash
python scripts/key_rotation.py --env production --dry-run
python scripts/key_rotation.py --env production --execute
```

### Generate Audit Report

```bash
python scripts/audit_report.py --range 90d --output reports/q3_audit.pdf
```

---

## Configuration

`config/config.yaml`:

```yaml
ciphertrust:
  host: "https://your-ct-manager.domain.com"
  username: "${CT_USERNAME}"
  password: "${CT_PASSWORD}"
  domain: "root"
  verify_ssl: true

rotation:
  default_interval_days: 90
  algorithms: ["AES-256", "RSA-2048"]
  notify_before_days: 14

reporting:
  output_dir: "./reports"
  format: "pdf"
  include_hash: true
```

---

## Core Scripts

### `cipher_connect.py`
Handles authentication, token management, and session reuse. All other scripts import from this module.

```python
from scripts.cipher_connect import CipherTrustSession

with CipherTrustSession() as ct:
    keys = ct.get("/v1/vault/keys")
```

### `key_rotation.py`
Identifies keys approaching expiration, rotates them, and logs cryptographic proof of rotation.

```bash
python scripts/key_rotation.py --algorithm AES-256 --threshold 14
```

### `policy_sync.py`
Reads encryption policies from YAML and pushes them to CipherTrust. Supports diff-preview before applying.

```bash
python scripts/policy_sync.py --policy-file policies/production.yaml --diff
python scripts/policy_sync.py --policy-file policies/production.yaml --apply
```

### `audit_report.py`
Generates timestamped, hash-verified compliance reports. Output is PDF with embedded metadata.

```bash
python scripts/audit_report.py --range 30d --format pdf --sign
```

---

## Use Cases

| Scenario | Script | Flags |
|---|---|---|
| Pre-audit key inventory | `audit_report.py` | `--range 90d` |
| Quarterly key rotation | `key_rotation.py` | `--execute --log-level DEBUG` |
| Policy drift detection | `policy_sync.py` | `--diff --no-apply` |
| Token health check | `cipher_connect.py` | `--verify` |

---

## Security Notes

- Never commit `config/config.yaml` — it is gitignored by default
- Use environment variables or a secrets manager for credentials
- All API calls use TLS; `verify_ssl: false` is for lab environments only
- Audit report hashes are SHA-256, suitable for SOX evidence packages

---

## Running Tests

```bash
pytest tests/ -v
pytest tests/ --cov=scripts --cov-report=html
```

---

## Roadmap

- [ ] Vormetric/DSM connector
- [ ] Slack/Teams alerting for rotation failures
- [ ] Multi-tenant domain support
- [ ] GitHub Actions CI pipeline

---

## License

MIT
