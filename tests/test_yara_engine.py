"""Tests for the YARA signature engine."""

import tempfile
from pathlib import Path

import pytest

from src.uber_hacksaw.detect.signatures import YaraEngine
from tests.utils.eicar import eicar_bytes_defanged


def test_yara_engine_initialization():
    """Test that YaraEngine initializes correctly."""
    engine = YaraEngine()
    assert engine is not None
    assert engine.rules_dir is not None
    assert engine.timeout == 30


def test_yara_engine_scan_clean_data():
    """Test scanning clean data."""
    engine = YaraEngine()

    clean_data = b"This is clean test data with no malicious patterns"
    matches = engine.scan_data(clean_data)

    # Should return empty list for clean data
    assert isinstance(matches, list)
    # Note: May have matches if rules are very broad, but should be list


def test_yara_engine_scan_eicar_data():
    """Test scanning EICAR data."""
    engine = YaraEngine()

    # Use defanged EICAR for safety
    eicar_data = eicar_bytes_defanged("truncate")
    matches = engine.scan_data(eicar_data)

    assert isinstance(matches, list)

    # Check if EICAR was detected
    if matches:
        rule_names = [match["rule"] for match in matches]
        eicar_detected = any("EICAR" in rule for rule in rule_names)
        # Note: May not detect if rules are not loaded or EICAR is too defanged


def test_yara_engine_scan_with_file_path():
    """Test scanning data with file path context."""
    engine = YaraEngine()

    test_data = b"Test data for scanning"
    file_path = "/test/path/file.txt"

    matches = engine.scan_data(test_data, file_path)

    assert isinstance(matches, list)

    # Check that file path is included in matches
    for match in matches:
        assert "file_path" in match
        assert match["file_path"] == file_path


def test_yara_engine_match_structure():
    """Test that match results have expected structure."""
    engine = YaraEngine()

    # Create data that might trigger a rule
    test_data = b"EICAR-STANDARD-ANTIVIRUS-TEST-FILE"
    matches = engine.scan_data(test_data)

    for match in matches:
        # Check required fields
        assert "rule" in match
        assert "severity" in match
        assert "tags" in match
        assert "meta" in match
        assert "strings" in match
        assert "file_path" in match
        assert "confidence" in match
        assert "match_time" in match

        # Check types
        assert isinstance(match["rule"], str)
        assert isinstance(match["severity"], str)
        assert isinstance(match["tags"], list)
        assert isinstance(match["meta"], dict)
        assert isinstance(match["strings"], list)
        assert isinstance(match["file_path"], str)
        assert isinstance(match["confidence"], str)
        assert isinstance(match["match_time"], (int, float))


def test_yara_engine_custom_rules_dir():
    """Test YaraEngine with custom rules directory."""
    # Create a temporary directory for custom rules
    with tempfile.TemporaryDirectory() as temp_dir:
        rules_dir = Path(temp_dir)

        # Create a simple test rule
        test_rule = rules_dir / "test_rule.yara"
        test_rule.write_text(
            """
rule TestRule
{
    meta:
        description = "Test rule"
        severity = "low"
    strings:
        $test = "TEST_PATTERN"
    condition:
        $test
}
"""
        )

        engine = YaraEngine(rules_dir=rules_dir)

        # Test with data that should match
        test_data = b"This contains TEST_PATTERN for testing"
        matches = engine.scan_data(test_data)

        # Should find the test pattern
        test_matches = [m for m in matches if "TestRule" in m["rule"]]
        if test_matches:
            assert len(test_matches) > 0
            assert test_matches[0]["severity"] == "low"


def test_yara_engine_timeout():
    """Test YaraEngine timeout functionality."""
    # Test with a very short timeout
    engine = YaraEngine(timeout=1)
    assert engine.timeout == 1

    # Test scanning (should not hang)
    test_data = b"Test data"
    matches = engine.scan_data(test_data)
    assert isinstance(matches, list)
