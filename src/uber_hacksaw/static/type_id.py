"""File type identification and parsing."""

from __future__ import annotations

import mimetypes
from pathlib import Path
from typing import Any

from loguru import logger

# Make python-magic optional to avoid Windows access violations
try:
    import magic

    MAGIC_AVAILABLE = True
except (ImportError, OSError, Exception) as e:
    MAGIC_AVAILABLE = False

    # Create a mock magic object for testing purposes
    class MockMagic:
        @staticmethod
        def from_buffer(data, mime=False):
            return None

    magic = MockMagic()
    logger.debug(f"python-magic not available: {e}")


def _detect_by_signature(data: bytes) -> str | None:
    """Detect file type by magic signatures."""
    signatures = {
        b"\x7fELF": {"type": "application/x-executable", "is": "is_executable"},
        b"MZ": {"type": "application/x-msdownload", "is": "is_executable"},
        b"PK": {"type": "application/zip", "is": "is_archive"},
        b"PK\x03\x04": {"type": "application/zip", "is": "is_archive"},
        b"PK\x05\x06": {"type": "application/zip", "is": "is_archive"},  # Empty ZIP
        b"PK\x07\x08": {"type": "application/zip", "is": "is_archive"},  # Spanned ZIP
        b"%PDF": {"type": "application/pdf", "is": "is_document"},
        b"<!DOCTYPE": {"type": "text/html", "is": "is_document"},
        b"<html": {"type": "text/html", "is": "is_document"},
        b"{": {"type": "application/json", "is": "is_document"},
        b"[": {"type": "application/json", "is": "is_document"},
        b"<?xml": {"type": "text/xml", "is": "is_document"},
        b"\x89PNG\r\n\x1a\n": {"type": "image/png", "is": "is_document"},
        b"\xff\xd8\xff": {"type": "image/jpeg", "is": "is_document"},
        b"GIF87a": {"type": "image/gif", "is": "is_document"},
        b"GIF89a": {"type": "image/gif", "is": "is_document"},
    }

    for signature, mime_details in signatures.items():
        if data.startswith(signature):
            return mime_details

    return {"type": None, "is": None}


def _detect_file_type_by_extension(file_path: Path) -> str | None:
    """Fallback if NO MIME types is detected. Use extension to detect file type."""
    extension = file_path.suffix.lower()
    logger.debug(f"Detecting file type by extension: {extension}")
    extension_mime_map = {
        ".txt": "text/plain",
        ".md": "text/markdown",
        ".json": "application/json",
        ".xml": "text/xml",
        ".html": "text/html",
        ".htm": "text/html",
        ".csv": "text/csv",
        ".zip": "application/zip",
        ".tar": "application/x-tar",
        ".gz": "application/gzip",
        ".bz2": "application/x-bzip2",
        ".7z": "application/x-7z-compressed",
        ".rar": "application/vnd.rar",
        ".exe": "application/x-msdownload",
        ".dll": "application/x-msdownload",
        ".so": "application/x-sharedlib",
        ".dylib": "application/x-mach-binary",
        ".py": "text/x-python",
        ".js": "application/javascript",
        ".css": "text/css",
        ".yaml": "application/x-yaml",
        ".yml": "application/x-yaml",
        ".pdf": "application/pdf",
        ".php": "application/x-httpd-php",
    }

    return extension_mime_map.get(extension, "application/octet-stream")


def detect_file_type(file_path: Path, data: bytes) -> dict[str, Any]:
    """Detect file type using multiple methods."""

    result = {
        "mime_type": None,
        "magic_type": None,
        "extension": file_path.suffix.lower(),
        "is_executable": False,
        "is_archive": False,
        "is_document": False,
        "file_name": file_path.name,
    }

    # MIME type detection
    logger.info(f"Detecting file type by extension: {file_path}")
    mime_type, _ = mimetypes.guess_type(str(file_path))
    result["mime_type"] = mime_type

    # Magic number detection
    # Magic number detection (only if available)
    if MAGIC_AVAILABLE:
        try:
            result["magic_type"] = magic.from_buffer(data, mime=True)
        except Exception as e:
            logger.debug(f"Magic detection failed for {file_path}: {e}")

    signature_type = _detect_by_signature(data)
    if signature_type["type"] is not None:
        # result["magic_type"] = signature_type["type"]
        result["mime_type"] = signature_type["type"]
        result[signature_type["is"]] = True
    else:
        logger.debug(f"No signature detected for {file_path}")

    if result["mime_type"] is None:
        result["mime_type"] = _detect_file_type_by_extension(file_path)

    logger.info(f"File type detection completed: {result['file_name']} -> {result['mime_type']}")

    return result
