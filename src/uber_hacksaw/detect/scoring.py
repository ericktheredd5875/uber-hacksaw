"""Heuristic scoring and detection."""

from __future__ import annotations

import math
from typing import Any


def calculate_entropy(data: bytes) -> float:
    """Calculate Shannon entropy of data."""
    if not data:
        return 0.0

    # Count frequency of each byte
    byte_counts = [0] * 256
    for byte in data:
        byte_counts[byte] += 1

    # Calculate entropy
    entropy = 0.0
    data_len = len(data)
    for count in byte_counts:
        if count > 0:
            probability = count / data_len
            entropy -= probability * math.log2(probability)

    return entropy


def analyze_heuristics(
    data: bytes, file_type: dict[str, Any], pe_info: dict[str, Any]
) -> list[dict[str, Any]]:
    """Analyze heuristic rules to detect suspicious patterns and characteristics."""
    findings = []

    # High entropy check
    entropy = calculate_entropy(data)
    if entropy > 7.5:
        findings.append(
            {
                "rule": "heuristic:high_entropy",
                "severity": "medium",
                "description": f"High entropy detected: {entropy:.2f}",
                "entropy": entropy,
            }
        )

    # PE specific heuristics
    if pe_info.get("is_pe", False):
        # Suspicious API imports
        if pe_info.get("suspicious_apis", False):
            findings.append(
                {
                    "rule": "heuristic:suspicious_apis",
                    "severity": "high",
                    "description": f"Suspicious APIs detected: {', '.join(pe_info['suspicious_apis'])}",
                    "apis": pe_info.get("suspicious_apis", []),
                }
            )

        # Packed Executable
        if pe_info.get("is_packed", False):
            findings.append(
                {
                    "rule": "heuristic:packed_executable",
                    "severity": "high",
                    "description": "Executable appears to be packed",
                    "entropy": pe_info.get("entropy", 0.0),
                }
            )

        # No imports (could be shellcode)
        if not pe_info.get("imports") and len(data) < 1024 * 1024:  # Less than 1MB
            findings.append(
                {
                    "rule": "heuristic:no_imports",
                    "severity": "medium",
                    "description": "PE file has no imports, could be shellcode",
                }
            )

    # Document-based heuristics
    if file_type.get("is_document", False):
        # Check for embedded objects or macros
        if b"VBA" in data or b"Macro" in data:
            findings.append(
                {
                    "rule": "heuristic:embedded_objects",
                    "severity": "high",
                    "description": "Document contains embedded objects or macros",
                }
            )

        # Check for suspicious URLs
        suspicious_urls = [b"http://", b"https://", b"ftp://"]
        url_count = sum(data.count(url) for url in suspicious_urls)
        if url_count > 5:
            findings.append(
                {
                    "rule": "heuristic:suspicious_urls",
                    "severity": "medium",
                    "description": f"Suspicious URLs detected: {url_count}",
                    "urls": [url.decode("utf-8", errors="ignore") for url in suspicious_urls],
                    "url_count": url_count,
                }
            )

    return findings
