"""File system utilities including hashing."""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any

import ppdeep
from loguru import logger


def sha256_hash(data: bytes) -> str:
    """Calculate SHA-256 hash of data."""
    return hashlib.sha256(data).hexdigest()


def fuzzy_hash_ppdeep(data: bytes) -> str | None:
    """Calculate ppdeep fuzzy hash of data."""
    try:
        if len(data) < 7:  # ppdeep requires at least 7 bytes
            return None

        return ppdeep.hash(data)
    except Exception as e:
        logger.debug(f"ppdeep hashing failed: {e}")
        return None


def calculate_file_hashes(file_path: Path) -> dict[str, Any]:
    """Calculate all hashes for a file."""
    try:
        data = file_path.read_bytes()
    except Exception as e:
        logger.debug(f"Could not read file {file_path}: {e}")
        return {"error": str(e)}

    return {
        "sha256": sha256_hash(data),
        "ppdeep": fuzzy_hash_ppdeep(data),
        "size": len(data),
    }


def calculate_data_hashes(data: bytes) -> dict[str, Any]:
    """Calculate all hashes for raw data."""
    return {
        "sha256": sha256_hash(data),
        "ppdeep": fuzzy_hash_ppdeep(data),
        "size": len(data),
    }


# Compare similarity of two hashes
def compare_fuzzy_hashes(hash1: str, hash2: str) -> int:
    """Compare two ppdeep hashes and return a similarity score (0-100)."""
    try:
        return ppdeep.compare(hash1, hash2)
    except Exception as e:
        logger.debug(f"ppdeep comparison failed: {e}")
        return 0
