"""Event fingerprinting for deduplication."""

import hashlib

from sentineltrace.core.models import NormalizedEvent


def compute_fingerprint(event: NormalizedEvent) -> str:
    material = event.fingerprint_material()
    return hashlib.sha256(material.encode("utf-8", errors="replace")).hexdigest()
