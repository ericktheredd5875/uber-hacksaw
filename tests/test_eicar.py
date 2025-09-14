"""Tests for EICAR detection functionality."""

import base64
from pathlib import Path

import pytest

from tests.utils.eicar import eicar_bytes_defanged, eicar_bytes_real


def test_eicar_real_bytes():
    """Test that real EICAR bytes are generated correctly."""
    eicar_bytes = eicar_bytes_real()
    assert isinstance(eicar_bytes, bytes)
    assert len(eicar_bytes) > 0
    # The EICAR string should be the canonical test string
    assert len(eicar_bytes) == 80  # This EICAR variant is 80 bytes
    assert eicar_bytes.startswith(b"X5O!P%@AP")


def test_eicar_defanged_truncated():
    """Test defanged EICAR with truncation."""
    defanged_bytes = eicar_bytes_defanged("truncate")
    assert isinstance(defanged_bytes, bytes)
    assert len(defanged_bytes) > 0
    # Should be shorter than real EICAR
    real_bytes = eicar_bytes_real()
    assert len(defanged_bytes) < len(real_bytes)


def test_eicar_defanged_mutated():
    """Test defanged EICAR with mutation."""
    defanged_bytes = eicar_bytes_defanged("mutate")
    assert isinstance(defanged_bytes, bytes)
    assert len(defanged_bytes) > 0
    # Should be same length as real EICAR but different content
    real_bytes = eicar_bytes_real()
    assert len(defanged_bytes) == len(real_bytes)
    assert defanged_bytes != real_bytes


def test_eicar_generation():
    """Test EICAR file generation."""
    from tests.utils.eicar import write_defanged_variants

    test_dir = Path(__file__).parent / "temp_eicar_test"
    test_dir.mkdir(exist_ok=True)

    try:
        created_files = write_defanged_variants(test_dir)
        assert len(created_files) >= 2

        for file_path in created_files:
            assert file_path.exists()
            assert file_path.stat().st_size > 0

    finally:
        # Clean up
        for file_path in test_dir.iterdir():
            file_path.unlink()
        test_dir.rmdir()


def test_benign_file_generation():
    """Test benign file generation."""
    from tests.utils.eicar import generate_benign_files

    test_dir = Path(__file__).parent / "temp_benign_test"
    test_dir.mkdir(exist_ok=True)

    try:
        created_files = list(generate_benign_files(test_dir))
        assert len(created_files) >= 1

        for file_path in created_files:
            assert file_path.exists()
            assert file_path.stat().st_size > 0

    finally:
        # Clean up
        for file_path in test_dir.iterdir():
            file_path.unlink()
        test_dir.rmdir()
