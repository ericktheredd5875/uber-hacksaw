"""Core scanning engine."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from loguru import logger

from ..detect.scoring import analyze_heuristics
from ..detect.signatures import YaraEngine
from ..io.collectors import FileFilter, collect_files
from ..io.fs_utils import calculate_file_hashes
from ..static.pe import analyze_pe
from ..static.type_id import detect_file_type


class ScanEngine:
    """Main scanning engine orchestrates all detection methods."""

    def __init__(self, rules_dir: Path | None = None, timeout: int = 30):
        self.yara_engine = YaraEngine(rules_dir, timeout)
        self.file_filter = FileFilter()

    def scan_file(self, file_path: Path) -> dict[str, Any]:
        """Scan a single file with all available detection methods."""
        result = {
            "target": str(file_path),
            "clean": True,
            "hits": [],
            "error": None,
        }

        try:
            # Read file data
            data = file_path.read_bytes()

            # Read & Calculate hashes
            hashes = calculate_file_hashes(file_path)
            result.update(hashes)

            # Detect file type
            file_type = detect_file_type(file_path, data)
            result.update(file_type)

            # PE analysis if applicable
            pe_info = {}
            if (
                file_type.get("is_executable", False)
                and file_type.get("mime_type") == "application/x-msdownload"
            ):
                pe_info = analyze_pe(data)
            result.update(pe_info)

            # YARA signature detection
            yara_hits = self.yara_engine.scan_data(data, str(file_path))
            result["hits"].extend(yara_hits)

            # Heuristic analysis
            heuristic_hits = analyze_heuristics(data, file_type, pe_info)
            result["hits"].extend(heuristic_hits)

            # Determine if clean
            result["clean"] = len(result["hits"]) == 0

        except Exception as e:
            result["error"] = f"scan-failed: {e.__class__.__name__}: {e}"
            logger.error(f"Failed to scan {file_path}: {e}")

        return result

    def scan_path(self, path: Path, recursive: bool = True) -> list[dict[str, Any]]:
        """Scan all files in a path."""
        results = []

        for file_path in collect_files(path, recursive, self.file_filter):
            result = self.scan_file(file_path)
            results.append(result)

        return results
