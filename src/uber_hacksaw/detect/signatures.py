"""YARA signature detection."""

from __future__ import annotations

import time
from pathlib import Path
from typing import Any

import yara
from loguru import logger


class YaraEngine:
    """YARA rule engine with caching and timeout support."""

    def __init__(self, rules_dir: Path | None = None, timeout: int = 30):
        self.rules_dir = rules_dir or Path(__file__).parent.parent / "core" / "rules" / "yara"
        self.timeout = timeout
        self._compiled_rules: dict[str, yara.Rules] = {}
        self._load_rules()

    def _load_rules(self):
        """Load and compile YARA rules from the rules directory."""
        if not self.rules_dir.exists():
            logger.warning(f"YARA Rules directory not found: {self.rules_dir}")
            return

        for rule_file in self.rules_dir.glob("*.yara"):
            try:
                rules = yara.compile(str(rule_file))
                self._compiled_rules[rule_file.stem] = rules
                logger.info(f"Loaded and compiled YARA rule: {rule_file.name}")
            except Exception as e:
                logger.error(f"Failed to compile YARA rule {rule_file}: {e}")

    def scan_data(self, data: bytes, file_path: str = "") -> list[dict[str, Any]]:
        """Scan data against all loaded YARA rules."""
        matches = []

        for rule_name, rules in self._compiled_rules.items():
            try:
                # Use a timeout for rule execution
                start_time = time.time()
                rule_matches = rules.match(data=data, timeout=self.timeout)

                for match in rule_matches:
                    match_info = {
                        "rule": f"Yara:{rule_name}:{match.rule}",
                        "severity": "medium",  # Default severity
                        "tags": list(match.tags),
                        "meta": match.meta,
                        "strings": [
                            {"name": s.identifier, "offset": s.instances[0].offset}
                            for s in match.strings
                        ],
                        "file_path": file_path,
                        "confidence": match.meta.get("confidence", "medium"),
                        "match_time": time.time() - start_time,
                    }

                    # Extract severity from meta if available
                    if "severity" in match.meta:
                        match_info["severity"] = match.meta["severity"]

                    matches.append(match_info)

                execution_time = time.time() - start_time
                if execution_time > self.timeout * 0.8:  # Warn if rule took too long
                    logger.warning(f"YARA rule {rule_name} took {execution_time:.2f}s to execute")

            except yara.TimeoutError:
                logger.warning(f"YARA rule {rule_name} timed out after {self.timeout} seconds")
            except Exception as e:
                logger.error(f"YARA rule {rule_name} error: {e}")

        return matches
