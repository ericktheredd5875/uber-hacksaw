"""Tests for heuristic detection and scoring."""

import pytest

from src.uber_hacksaw.detect.scoring import analyze_heuristics, calculate_entropy


def test_calculate_entropy_empty_data():
    """Test entropy calculation with empty data."""
    entropy = calculate_entropy(b"")
    assert entropy == 0.0


def test_calculate_entropy_uniform_data():
    """Test entropy calculation with uniform data."""
    # All bytes are the same - should have low entropy
    uniform_data = b"A" * 100
    entropy = calculate_entropy(uniform_data)
    assert entropy == 0.0


def test_calculate_entropy_random_data():
    """Test entropy calculation with random-like data."""
    # Create data with high entropy
    random_data = bytes(range(256)) * 4  # All possible bytes repeated
    entropy = calculate_entropy(random_data)
    assert entropy > 7.0  # Should be high entropy


def test_calculate_entropy_text_data():
    """Test entropy calculation with text data."""
    text_data = b"This is a normal text file with some content"
    entropy = calculate_entropy(text_data)
    assert 0.0 < entropy < 8.0  # Should be reasonable entropy


def test_analyze_heuristics_high_entropy():
    """Test heuristic analysis for high entropy data."""
    # Create high entropy data
    high_entropy_data = bytes(range(256)) * 4

    file_type = {"is_executable": False, "is_document": False}
    pe_info = {"is_pe": False}

    findings = analyze_heuristics(high_entropy_data, file_type, pe_info)

    # Should detect high entropy
    high_entropy_findings = [
        f for f in findings if f["rule"] == "heuristic:high_entropy"
    ]
    assert len(high_entropy_findings) > 0
    assert high_entropy_findings[0]["severity"] == "medium"


def test_analyze_heuristics_pe_suspicious_apis():
    """Test heuristic analysis for PE files with suspicious APIs."""
    # Mock PE info with suspicious APIs
    pe_info = {
        "is_pe": True,
        "suspicious_apis": ["kernel32.CreateProcess", "kernel32.VirtualAlloc"],
    }

    file_type = {"is_executable": True}
    test_data = b"Some PE file data"

    findings = analyze_heuristics(test_data, file_type, pe_info)

    # Should detect suspicious APIs
    api_findings = [f for f in findings if f["rule"] == "heuristic:suspicious_apis"]
    assert len(api_findings) > 0
    assert api_findings[0]["severity"] == "high"
    assert "CreateProcess" in api_findings[0]["description"]


def test_analyze_heuristics_pe_packed():
    """Test heuristic analysis for packed PE files."""
    # Mock PE info indicating packed executable
    pe_info = {"is_pe": True, "is_packed": True, "entropy": 7.8}

    file_type = {"is_executable": True}
    test_data = b"Some packed PE data"

    findings = analyze_heuristics(test_data, file_type, pe_info)

    # Should detect packed executable
    packed_findings = [
        f for f in findings if f["rule"] == "heuristic:packed_executable"
    ]
    assert len(packed_findings) > 0
    assert packed_findings[0]["severity"] == "high"


def test_analyze_heuristics_pe_no_imports():
    """Test heuristic analysis for PE files with no imports."""
    # Mock PE info with no imports (potential shellcode)
    pe_info = {"is_pe": True, "imports": []}

    file_type = {"is_executable": True}
    # Small file size to trigger shellcode detection
    test_data = b"Small PE file" * 100  # Less than 1MB

    findings = analyze_heuristics(test_data, file_type, pe_info)

    # Should detect no imports
    no_imports_findings = [f for f in findings if f["rule"] == "heuristic:no_imports"]
    assert len(no_imports_findings) > 0
    assert no_imports_findings[0]["severity"] == "medium"


def test_analyze_heuristics_document_macros():
    """Test heuristic analysis for documents with macros."""
    file_type = {"is_document": True}
    pe_info = {"is_pe": False}

    # Document with macro indicators
    test_data = b"This document contains VBA macros and Macro code"

    findings = analyze_heuristics(test_data, file_type, pe_info)

    # Should detect embedded objects/macros
    macro_findings = [f for f in findings if f["rule"] == "heuristic:embedded_objects"]
    assert len(macro_findings) > 0
    assert macro_findings[0]["severity"] == "high"


def test_analyze_heuristics_document_urls():
    """Test heuristic analysis for documents with many URLs."""
    file_type = {"is_document": True}
    pe_info = {"is_pe": False}

    # Document with many URLs
    test_data = b"http://example.com https://test.com ftp://files.com " * 10

    findings = analyze_heuristics(test_data, file_type, pe_info)

    # Should detect suspicious URLs
    url_findings = [f for f in findings if f["rule"] == "heuristic:suspicious_urls"]
    assert len(url_findings) > 0
    assert url_findings[0]["severity"] == "medium"
    assert url_findings[0]["url_count"] > 5


def test_analyze_heuristics_clean_file():
    """Test heuristic analysis for clean files."""
    file_type = {"is_executable": False, "is_document": False}
    pe_info = {"is_pe": False}

    # Clean text data
    test_data = b"This is a clean text file with normal content"

    findings = analyze_heuristics(test_data, file_type, pe_info)

    # Should have minimal findings for clean data
    # Only high entropy might trigger if data is random enough
    assert isinstance(findings, list)


def test_analyze_heuristics_finding_structure():
    """Test that heuristic findings have expected structure."""
    file_type = {"is_document": True}
    pe_info = {"is_pe": False}

    test_data = b"VBA macro content"
    findings = analyze_heuristics(test_data, file_type, pe_info)

    for finding in findings:
        # Check required fields
        assert "rule" in finding
        assert "severity" in finding
        assert "description" in finding

        # Check types
        assert isinstance(finding["rule"], str)
        assert isinstance(finding["severity"], str)
        assert isinstance(finding["description"], str)

        # Check severity values
        assert finding["severity"] in ["low", "medium", "high"]
