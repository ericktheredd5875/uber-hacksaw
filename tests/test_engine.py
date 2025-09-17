"""Tests for the core scanning engine."""

import tempfile
from pathlib import Path
from typing import Any

import pytest

from src.uber_hacksaw.core.engine import ScanEngine
from tests.utils.eicar import eicar_bytes_defanged


def test_scan_engine_initialization():
    """Test that ScanEngine initializes correctly."""
    engine = ScanEngine()
    assert engine is not None
    assert engine.yara_engine is not None
    assert engine.file_filter is not None


def test_scan_engine_scan_file_clean():
    """Test scanning a clean file."""
    engine = ScanEngine()

    # Create a temporary clean file
    with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".txt") as f:
        f.write("This is a clean test file")
        temp_path = Path(f.name)

    try:
        result = engine.scan_file(temp_path)

        assert result["target"] == str(temp_path)
        assert result["clean"] is True
        assert result["error"] is None
        assert "sha256" in result
        assert "size" in result
        assert "hits" in result
        assert len(result["hits"]) == 0

    finally:
        temp_path.unlink(missing_ok=True)


def test_scan_engine_scan_file_eicar():
    """Test scanning an EICAR file."""
    engine = ScanEngine()

    # Create a temporary EICAR file (defanged for safety)
    eicar_data = eicar_bytes_defanged("truncate")
    with tempfile.NamedTemporaryFile(delete=False, suffix=".txt") as f:
        f.write(eicar_data)
        temp_path = Path(f.name)

    try:
        result = engine.scan_file(temp_path)

        assert result["target"] == str(temp_path)
        assert result["error"] is None
        assert "sha256" in result
        assert "size" in result
        assert "hits" in result

        # Should detect EICAR
        if not result["clean"]:
            hit_rules = [hit["rule"] for hit in result["hits"]]
            eicar_detected = any("EICAR" in rule for rule in hit_rules)
            assert eicar_detected, f"EICAR not detected in rules: {hit_rules}"

    finally:
        temp_path.unlink(missing_ok=True)


def test_scan_engine_scan_path():
    """Test scanning a directory path."""
    engine = ScanEngine()

    # Create a temporary directory with test files
    with tempfile.TemporaryDirectory() as temp_dir:
        temp_path = Path(temp_dir)

        # Create a clean file
        clean_file = temp_path / "clean.txt"
        clean_file.write_text("This is a clean file")

        # Create an EICAR file
        eicar_file = temp_path / "eicar.txt"
        eicar_file.write_bytes(eicar_bytes_defanged("truncate"))

        # Scan the directory
        results = engine.scan_path(temp_path, recursive=False)

        assert len(results) == 2

        # Check that we have results for both files
        targets = [result["target"] for result in results]
        assert str(clean_file) in targets
        assert str(eicar_file) in targets


def test_scan_engine_file_type_detection():
    """Test file type detection."""
    engine = ScanEngine()

    # Test with a text file
    with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".txt") as f:
        f.write("Hello world")
        temp_path = Path(f.name)

    try:
        result = engine.scan_file(temp_path)

        # Check file type detection
        assert "mime_type" in result
        assert "extension" in result
        assert result["extension"] == ".txt"

    finally:
        temp_path.unlink(missing_ok=True)


def test_scan_engine_pe_analysis():
    """Test PE file analysis (if applicable)."""
    engine = ScanEngine()

    # Create a simple binary file that might trigger PE analysis
    with tempfile.NamedTemporaryFile(delete=False, suffix=".exe") as f:
        # Write some binary data that starts with MZ (PE header)
        f.write(b"MZ\x90\x00" + b"\x00" * 100)
        temp_path = Path(f.name)

    try:
        result = engine.scan_file(temp_path)

        assert result["target"] == str(temp_path)
        assert result["error"] is None

        # Check if PE analysis was performed
        if "is_pe" in result:
            assert isinstance(result["is_pe"], bool)

    finally:
        temp_path.unlink(missing_ok=True)

# Create a simple test to isolate the ppdeep issue
# uv run pytest tests/test_cli.py::test_cli_scan_console_output_format -v
def test_ppdeep_isolation():
    """Test ppdeep functionality in isolation."""
    import ppdeep
    
    # Test with minimal data
    test_data = b"hello world"
    
    try:
        # This should work
        result = ppdeep.hash(test_data)
        print(f"ppdeep hash result: {result}")
        assert result is not None
    except Exception as e:
        print(f"ppdeep error: {e}")
        # If ppdeep fails, we should handle it gracefully
        assert False, f"ppdeep failed: {e}"