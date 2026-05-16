"""
key_rotation.py
Identifies expiring keys in CipherTrust and performs automated rotation
with cryptographic proof of rotation logged for compliance.
"""

import argparse
import hashlib
import json
import logging
from datetime import datetime, timedelta
from scripts.cipher_connect import CipherTrustSession
from scripts.utils import setup_logging, write_audit_entry

logger = logging.getLogger(__name__)


def get_expiring_keys(ct: CipherTrustSession, threshold_days: int, algorithm: str = None) -> list:
    """Fetch keys expiring within threshold_days."""
    params = {"limit": 500, "skip": 0}
    if algorithm:
        params["algorithm"] = algorithm
    
    keys = ct.get("/v1/vault/keys", params=params).get("resources", [])
    cutoff = datetime.utcnow() + timedelta(days=threshold_days)
    
    expiring = []
    for key in keys:
        expires = key.get("meta", {}).get("expirationDate")
        if expires:
            exp_dt = datetime.fromisoformat(expires.replace("Z", "+00:00")).replace(tzinfo=None)
            if exp_dt <= cutoff:
                expiring.append(key)
    
    logger.info(f"Found {len(expiring)} keys expiring within {threshold_days} days")
    return expiring


def rotate_key(ct: CipherTrustSession, key: dict, dry_run: bool = True) -> dict:
    """Rotate a single key and return rotation record."""
    key_id = key["id"]
    key_name = key.get("name", key_id)
    
    if dry_run:
        logger.info(f"[DRY RUN] Would rotate key: {key_name} ({key_id})")
        return {"key_id": key_id, "key_name": key_name, "status": "dry_run", "timestamp": datetime.utcnow().isoformat()}
    
    # Perform rotation via CipherTrust API
    new_key = ct.post(f"/v1/vault/keys/{key_id}/rotate", {
        "algorithm": key.get("algorithm"),
        "size": key.get("size"),
        "meta": {"rotatedFrom": key_id, "rotatedAt": datetime.utcnow().isoformat()}
    })
    
    record = {
        "old_key_id": key_id,
        "new_key_id": new_key["id"],
        "key_name": key_name,
        "algorithm": key.get("algorithm"),
        "timestamp": datetime.utcnow().isoformat(),
        "status": "rotated",
        "proof_hash": hashlib.sha256(
            json.dumps(new_key, sort_keys=True).encode()
        ).hexdigest()
    }
    
    logger.info(f"Rotated key {key_name}: {key_id} -> {new_key['id']}")
    write_audit_entry("KEY_ROTATION", record)
    return record


def main():
    parser = argparse.ArgumentParser(description="CipherTrust Key Rotation Automation")
    parser.add_argument("--threshold", type=int, default=14, help="Days until expiration threshold")
    parser.add_argument("--algorithm", type=str, help="Filter by algorithm (e.g. AES-256)")
    parser.add_argument("--env", type=str, default="default", help="Environment label for logs")
    parser.add_argument("--dry-run", action="store_true", default=True, help="Preview without rotating")
    parser.add_argument("--execute", action="store_true", help="Actually perform rotation")
    args = parser.parse_args()

    setup_logging()
    dry_run = not args.execute

    if dry_run:
        logger.warning("Running in DRY RUN mode. Pass --execute to perform actual rotation.")

    with CipherTrustSession() as ct:
        expiring = get_expiring_keys(ct, args.threshold, args.algorithm)
        results = [rotate_key(ct, key, dry_run=dry_run) for key in expiring]

    summary = {
        "env": args.env,
        "run_at": datetime.utcnow().isoformat(),
        "dry_run": dry_run,
        "keys_found": len(expiring),
        "keys_rotated": sum(1 for r in results if r["status"] == "rotated"),
        "results": results
    }
    
    print(json.dumps(summary, indent=2))
    return summary


if __name__ == "__main__":
    main()
