"""Tests for file type detection."""

import tempfile
from pathlib import Path

import pytest

from src.uber_hacksaw.static.type_id import detect_file_type


def test_detect_file_type_text_file():
    """Test file type detection for text files."""
    test_path = Path("test.txt")
    test_data = b"Hello, world!"

    result = detect_file_type(test_path, test_data)

    assert result["extension"] == ".txt"
    assert result["is_executable"] is False
    assert result["is_archive"] is False
    assert result["is_document"] is False


def test_detect_file_type_pe_file():
    """Test file type detection for PE files."""
    test_path = Path("test.exe")
    # PE header starts with MZ
    test_data = b"MZ\x90\x00" + b"\x00" * 100

    result = detect_file_type(test_path, test_data)

    assert result["extension"] == ".exe"
    assert result["is_executable"] is True
    assert result["mime_type"] == "application/x-msdownload"


def test_detect_file_type_elf_file():
    """Test file type detection for ELF files."""
    test_path = Path("test")
    # ELF header starts with \x7fELF
    test_data = b"\x7fELF" + b"\x00" * 100

    result = detect_file_type(test_path, test_data)

    assert result["is_executable"] is True
    assert result["mime_type"] == "application/x-executable"


def test_detect_file_type_zip_file():
    """Test file type detection for ZIP files."""
    test_path = Path("test.zip")
    # ZIP files start with PK
    test_data = b"PK\x03\x04" + b"\x00" * 100

    result = detect_file_type(test_path, test_data)

    assert result["extension"] == ".zip"
    assert result["is_archive"] is True
    assert result["mime_type"] == "application/zip"


def test_detect_file_type_pdf_file():
    """Test file type detection for PDF files."""
    test_path = Path("test.pdf")
    # PDF files start with %PDF
    test_data = b"%PDF-1.4" + b"\x00" * 100

    result = detect_file_type(test_path, test_data)

    assert result["extension"] == ".pdf"
    assert result["is_document"] is True
    assert result["mime_type"] == "application/pdf"


def test_detect_file_type_html_file():
    """Test file type detection for HTML files."""
    test_path = Path("test.html")
    # HTML files start with <!DOCTYPE or <html
    test_data = b"<!DOCTYPE html><html><body>Hello</body></html>"

    result = detect_file_type(test_path, test_data)

    assert result["extension"] == ".html"
    assert result["is_document"] is True
    assert result["mime_type"] == "text/html"


def test_detect_file_type_json_file():
    """Test file type detection for JSON files."""
    test_path = Path("test.json")
    # JSON files start with { or [
    test_data = b'{"key": "value"}'

    result = detect_file_type(test_path, test_data)

    assert result["extension"] == ".json"
    assert result["is_document"] is True
    assert result["mime_type"] == "application/json"


def test_detect_file_type_xml_file():
    """Test file type detection for XML files."""
    test_path = Path("test.xml")
    # XML files start with <?xml
    test_data = b'<?xml version="1.0"?><root>test</root>'

    result = detect_file_type(test_path, test_data)

    assert result["extension"] == ".xml"
    assert result["is_document"] is True
    assert result["mime_type"] == "text/xml"


def test_detect_file_type_unknown():
    """Test file type detection for unknown file types."""
    test_path = Path("test.unknown")
    test_data = b"Some random binary data \x00\x01\x02\x03"

    result = detect_file_type(test_path, test_data)

    assert result["extension"] == ".unknown"
    assert result["is_executable"] is False
    assert result["is_archive"] is False
    assert result["is_document"] is False


def test_detect_file_type_result_structure():
    """Test that file type detection returns expected structure."""
    test_path = Path("test.txt")
    test_data = b"Test data"

    result = detect_file_type(test_path, test_data)

    # Check required fields
    assert "mime_type" in result
    assert "magic_type" in result
    assert "extension" in result
    assert "is_executable" in result
    assert "is_archive" in result
    assert "is_document" in result

    # Check types
    assert isinstance(result["extension"], str)
    assert isinstance(result["is_executable"], bool)
    assert isinstance(result["is_archive"], bool)
    assert isinstance(result["is_document"], bool)


def test_detect_file_type_magic_detection():
    """Test magic number detection (if available)."""
    test_path = Path("test.txt")
    test_data = b"Test data"

    result = detect_file_type(test_path, test_data)

    # Magic type might be None if python-magic is not available or fails
    # but the field should exist
    assert "magic_type" in result


def test_detect_file_type_mime_detection():
    """Test MIME type detection."""
    test_path = Path("test.txt")
    test_data = b"Test data"

    result = detect_file_type(test_path, test_data)

    # MIME type should be detected based on extension
    # Might be None if mimetypes can't determine it
    assert "mime_type" in result
