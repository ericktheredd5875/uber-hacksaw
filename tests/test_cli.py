"""Tests for the CLI module."""

import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict

import pytest


# uv run python -m uber_hacksaw.cli --help
def test_cli_help():
    """Test that CLI help is displayed correctly."""
    result = subprocess.run(
        ["uv", "run", "python", "-m", "uber_hacksaw.cli", "--help"],
        capture_output=True,
        text=True,
        cwd=Path(__file__).parent.parent,
        env={
            **os.environ,
            "NO_COLOR": "1",
            "TERM": "dumb",  # Disable colors
            "FORCE_COLOR": "0",  # Disable colors
        },
    )

    print(result.stdout)
    assert result.returncode == 0
    assert "uber-hacksaw" in result.stdout
    assert "--help" in result.stdout
    assert "scan" in result.stdout


def test_cli_scan_nonexistent_path():
    """Test CLI error handling for nonexistent paths."""
    result = subprocess.run(
        ["uv", "run", "python", "-m", "uber_hacksaw.cli", "--path", "nonexistent"],
        capture_output=True,
        text=True,
        cwd=Path(__file__).parent.parent,
    )
    assert result.returncode == 2
    assert "Error" in result.stderr


def test_cli_scan_empty_stdin():
    """Test CLI with empty stdin."""
    result = subprocess.run(
        ["uv", "run", "python", "-m", "uber_hacksaw.cli", "scan", "--stdin"],
        input="",
        capture_output=True,
        text=True,
        cwd=Path(__file__).parent.parent,
    )
    assert result.returncode == 0
    assert "CLEAN" in result.stdout or "no detections" in result.stdout


def test_cli_scan_json_output():
    """Test CLI JSON output format."""
    # Create a temporary test file
    test_file = Path(__file__).parent / "test_hello.txt"
    test_file.write_text("hello world")

    try:
        result = subprocess.run(
            [
                "uv",
                "run",
                "python",
                "-m",
                "uber_hacksaw.cli",
                "scan",
                "--path",
                str(test_file),
                "--output",
                "json",
            ],
            capture_output=True,
            text=True,
            cwd=Path(__file__).parent.parent,
        )
        assert result.returncode == 0

        # Parse JSON output
        output_data = json.loads(result.stdout)
        assert isinstance(output_data, list)
        assert len(output_data) == 1

        scan_result = output_data[0]
        assert "target" in scan_result
        assert "type" in scan_result
        assert "sha256" in scan_result
        assert "size" in scan_result
        assert "hits" in scan_result
        assert "clean" in scan_result
        assert scan_result["clean"] is True

    finally:
        test_file.unlink(missing_ok=True)


def test_cli_scan_console_output_format():
    """Test CLI console output includes file type (M0 acceptance criteria)."""
    # Create a temporary test file
    test_file = Path(__file__).parent / "test_hello.txt"
    test_file.write_text("hello world")

    try:
        result = subprocess.run(
            [
                "uv",
                "run",
                "python",
                "-m",
                "uber_hacksaw.cli",
                "scan",
                "--path",
                str(test_file),
                "--output",
                "console",
            ],
            capture_output=True,
            text=True,
            cwd=Path(__file__).parent.parent,
        )
        assert result.returncode == 0

        # M0 acceptance criteria: should show (path, type, size, hash)
        # Format: [CLEAN] path (type): size bytes
        assert "[CLEAN]" in result.stdout
        assert "text/plain" in result.stdout  # file type
        assert "bytes" in result.stdout  # size

    finally:
        test_file.unlink(missing_ok=True)


def test_cli_scan_directory():
    """Test CLI scanning a directory."""
    # Use the existing tests directory
    tests_dir = Path(__file__).parent

    # uv run python -m uber_hacksaw.cli --path tests --output json
    result = subprocess.run(
        [
            "uv",
            "run",
            "python",
            "-m",
            "uber_hacksaw.cli",
            "scan",
            "--path",
            str(tests_dir),
            "--output",
            "json",
        ],
        capture_output=True,
        text=True,
        cwd=Path(__file__).parent.parent,
    )
    # May return 0 (clean) or 1 (detections found)
    assert result.returncode in [0, 1]

    # Parse JSON output
    output_data = json.loads(result.stdout)
    assert isinstance(output_data, list)
    assert len(output_data) > 0

    # Check structure of results
    for scan_result in output_data:
        assert "target" in scan_result
        assert "type" in scan_result
        assert "clean" in scan_result
        assert "hits" in scan_result


def test_cli_scan_no_args():
    """Test CLI with no arguments (should show help)."""
    result = subprocess.run(
        ["uv", "run", "python", "-m", "uber_hacksaw.cli"],
        capture_output=True,
        text=True,
        cwd=Path(__file__).parent.parent,
    )
    # Should show help or usage error
    assert result.returncode in [0, 2]
