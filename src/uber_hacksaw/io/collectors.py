"""File collection and filtering utilities."""

from __future__ import annotations

import mimetypes
from collections.abc import Iterable
from pathlib import Path

from loguru import logger


class FileFilter:
    """Configuration for file filtering during collection."""

    def __init__(
        self,
        max_size: int = 100 * 1024 * 1024,  # 100MB
        min_size: int = 0,
        allowed_extensions: set[str] | None = None,
        blocked_extensions: set[str] | None = None,
        allowed_mime_types: set[str] | None = None,
        blocked_mime_types: set[str] | None = None,
    ):
        self.max_size = max_size
        self.min_size = min_size
        self.allowed_extensions = allowed_extensions or set()
        self.blocked_extensions = blocked_extensions or {".tmp", ".log", ".cache"}
        self.allowed_mime_types = allowed_mime_types or set()
        self.blocked_mime_types = blocked_mime_types or set()

    def should_include(self, file_path: Path, file_size: int) -> bool:
        """Check if a file should be included based on filters."""
        # Size Checks
        if file_size < self.min_size or file_size > self.max_size:
            return False

        # Extension Checks
        if self.allowed_extensions and file_path.suffix.lower() not in self.allowed_extensions:
            return False
        if file_path.suffix.lower() in self.blocked_extensions:
            return False

        # MIME Type checks
        mime_type, _ = mimetypes.guess_type(str(file_path))
        if mime_type:
            if self.allowed_mime_types and mime_type not in self.allowed_mime_types:
                return False
            if mime_type in self.blocked_mime_types:
                return False

        return True


def collect_files(
    path: Path, recursive: bool, file_filter: FileFilter | None = None
) -> Iterable[Path]:
    """Collect files from a path with optional filtering."""
    if file_filter is None:
        file_filter = FileFilter()

    if path.is_file():
        try:
            file_size = path.stat().st_size
            if file_filter.should_include(path, file_size):
                yield path

        except OSError as e:
            logger.debug(f"Could not stat file {path}: {e}")

    elif path.is_dir():
        pattern = "**/*" if recursive else "*"
        for file_path in path.glob(pattern):
            if file_path.is_file():
                try:
                    file_size = file_path.stat().st_size
                    if file_filter.should_include(file_path, file_size):
                        yield file_path
                except OSError as e:
                    logger.debug(f"Could not stat file {file_path}: {e}")
    else:
        logger.debug(f"Path does not exist or is not a file/directory: {path}")
