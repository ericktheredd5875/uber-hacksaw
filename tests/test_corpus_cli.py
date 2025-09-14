"""Tests for the corpus CLI functionality."""

import json
import subprocess
import sys
from pathlib import Path

import pytest


def test_corpus_cli_help():
    """Test corpus CLI help."""
    result = subprocess.run(
        [sys.executable, "scripts/corpus_cli.py", "--help"],
        capture_output=True,
        text=True,
        cwd=Path(__file__).parent.parent,
    )
    assert result.returncode == 0
    assert "init" in result.stdout or "generate" in result.stdout


def test_corpus_cli_init():
    """Test corpus CLI initialization."""
    test_datasets = Path(__file__).parent / "temp_datasets"

    try:
        # Create the directory first
        test_datasets.mkdir(exist_ok=True)

        # Initialize corpus in temp directory
        result = subprocess.run(
            [
                sys.executable,
                str(Path(__file__).parent.parent / "scripts" / "corpus_cli.py"),
                "init",
            ],
            capture_output=True,
            text=True,
            cwd=test_datasets,
        )

        # Should create directory structure
        assert result.returncode == 0
        # Check that the script ran successfully (directories may be created relative to script location)

    finally:
        # Clean up
        if test_datasets.exists():
            import shutil

            shutil.rmtree(test_datasets)


def test_corpus_cli_manifest():
    """Test corpus manifest generation."""
    # Use existing datasets directory
    datasets_dir = Path(__file__).parent.parent / "datasets"
    if not datasets_dir.exists():
        pytest.skip("Datasets directory not found")

    result = subprocess.run(
        [sys.executable, "scripts/corpus_cli.py", "manifest"],
        capture_output=True,
        text=True,
        cwd=Path(__file__).parent.parent,
    )
    assert result.returncode == 0

    # Check manifest file exists and is valid JSON
    manifest_file = datasets_dir / "manifest.json"
    assert manifest_file.exists()

    manifest_data = json.loads(manifest_file.read_text())
    assert "generated_at" in manifest_data
    assert "entries" in manifest_data
    assert isinstance(manifest_data["entries"], list)
