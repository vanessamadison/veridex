# HIPAA Compliance Validator and Immutable Audit Logger
import re
import hashlib
import time
import json
from typing import Dict, Any, List

PII_PATTERNS = [
    re.compile(r'\b\d{3}-\d{2}-\d{4}\b'),
    re.compile(r'(\+?\d[\d\-\s]{7,}\d)'),
    re.compile(r'[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}')
]

class AuditLogger:
    def __init__(self, path: str):
        self.path = path
        try:
            with open(self.path, 'r') as f:
                lines = f.read().strip().splitlines()
            self.prev_hash = lines[-1].split(',')[0] if lines else 'GENESIS'
        except Exception:
            self.prev_hash = 'GENESIS'

    def log(self, actor: str, action: str, details: Dict[str, Any]):
        rec = {
            'ts': int(time.time()),
            'actor': actor,
            'action': action,
            'details': details
        }
        payload = json.dumps(rec, sort_keys=True)
        h = hashlib.sha256((self.prev_hash + '|' + payload).encode()).hexdigest()
        line = h + ',' + payload + '\n'
        with open(self.path, 'a') as f:
            f.write(line)
        self.prev_hash = h

def contains_pii(text: str) -> bool:
    if not isinstance(text, str):
        return False
    for p in PII_PATTERNS:
        if p.search(text):
            return True
    return False

def minimize_record(record: Dict[str, Any], minimize_fields: List[str]) -> Dict[str, Any]:
    r = dict(record)
    for k in minimize_fields:
        if k in r:
            r[k] = None
    return r