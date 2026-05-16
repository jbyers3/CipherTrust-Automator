"""
utils.py
Shared utilities: logging setup, audit trail writing, config helpers.
"""

import json
import logging
import logging.config
import os
import yaml
from datetime import datetime
from pathlib import Path

LOG_DIR = Path(__file__).parent.parent / "logs"
AUDIT_LOG = LOG_DIR / "audit_trail.jsonl"


def setup_logging(level: str = "INFO"):
    LOG_DIR.mkdir(exist_ok=True)
    logging.basicConfig(
        level=getattr(logging, level.upper(), logging.INFO),
        format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
        handlers=[
            logging.StreamHandler(),
            logging.FileHandler(LOG_DIR / "ciphertrust_automator.log"),
        ],
    )


def write_audit_entry(event_type: str, data: dict):
    """Append a JSON line to the immutable audit trail."""
    LOG_DIR.mkdir(exist_ok=True)
    entry = {
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "event_type": event_type,
        "operator": os.environ.get("USER", "unknown"),
        "data": data,
    }
    with open(AUDIT_LOG, "a") as f:
        f.write(json.dumps(entry) + "\n")


def load_yaml(path: str) -> dict:
    with open(path, "r") as f:
        return yaml.safe_load(f)
