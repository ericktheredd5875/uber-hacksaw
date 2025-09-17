# src/uber-hacksaw/cli/__init__.py
from __future__ import annotations

import base64
import hashlib
import json
import mimetypes
import sys
from collections.abc import Iterable
from pathlib import Path
from typing import Any

import typer

from ..core.engine import ScanEngine
from ..io.fs_utils import calculate_data_hashes
from ..static.type_id import detect_file_type

app = typer.Typer(add_completion=False, help="uber-hacksaw CLI")


@app.callback()
def main():
    """uber-hacksaw - Malware Scanner"""
    pass


# Canonical EICAR test string (base64, to avoid accidental AV triggers in source scanners)
_EICAR_B64 = (
    "WDVPIVAlQEFQWzRcUFpYNTQoUF4pQUNIRU9Z"
    "RDU1KSMkKioqQH5fW10kUEVQWzRdJD9QWzBd"
    "JCQhQCMkXiFaQEF+QG5vQGJvZHkgbmljZSE="
)
_EICAR_CANON = base64.b64decode(_EICAR_B64)
_EICAR_MARKER = b"EICAR-STANDARD-ANTIVIRUS-TEST-FILE"


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _detect_bytes(data: bytes) -> list[dict[str, Any]]:
    """Tiny built-in detector for EICAR (canonical + marker)."""
    # TODO: replace with real engine later
    hits: list[dict[str, Any]] = []
    if _EICAR_CANON in data:
        hits.append({"rule": "EICAR:canonical", "severity": "high"})
    elif _EICAR_MARKER in data:
        hits.append({"rule": "EICAR:marker", "severity": "low"})

    return hits


def _scan_bytes_obj(
    label: str, data: bytes, file_path: Path | None = None
) -> dict[str, Any]:

    hits = _detect_bytes(data)

    # Use the comprehensive file type detection
    if file_path or label != "<stdin>":
        file_type_result = detect_file_type(file_path or Path(label), data)
        file_type = file_type_result["mime_type"]
    else:
        file_type = "application/octet-stream"

    return {
        "target": label,
        "type": file_type,
        "sha256": _sha256(data),
        "size": len(data),
        "hits": hits,
        "clean": len(hits) == 0,
    }


def _iter_files(path: Path, recursive: bool) -> Iterable[Path]:
    if path.is_file():
        yield path
    elif path.is_dir():
        it = path.rglob("*") if recursive else path.iterdir()
        for p in it:
            if p.is_file():
                yield p


def _scan_path(path: Path, recursive: bool) -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []
    for p in _iter_files(path, recursive):
        try:
            data = p.read_bytes()
        except Exception as e:
            results.append(
                {
                    "target": str(p),
                    "error": f"read-failed: {e.__class__.__name__}: {e}",
                    "hits": [],
                    "clean": True,
                }
            )
            continue

        results.append(_scan_bytes_obj(str(p), data))

    return results


PATH_OPTION = typer.Option(None, "--path", "-p", help="File or directory to scan.")
STDIN_OPTION = typer.Option(
    False, "--stdin", "-s", help="Read bytes from STDIN (pipe input)."
)
RECURSIVE_OPTION = typer.Option(
    True, "--recursive/--no-recursive", "-r", help="Scan directories recursively."
)
OUTPUT_OPTION = typer.Option(
    "console", "--output", "-o", help="Output format: console | JSON"
)


@app.command(name="scan")
def scan(
    path: Path | None = PATH_OPTION,
    stdin: bool = STDIN_OPTION,
    recursive: bool = RECURSIVE_OPTION,
    output: str = OUTPUT_OPTION,
) -> None:
    """
    Scan files, directories, or raw bytes from STDIN.
    Exit code 0 if clean, 1 if any detections, 2 on usage errors.
    """

    engine = ScanEngine()
    results: list[dict[str, Any]] = []
    if stdin:
        data = sys.stdin.buffer.read()
        result = {
            "target": "<stdin>",
            "sha256": _sha256(data),
            "size": len(data),
            "hits": [],
            "clean": True,
        }

        # Calculate hashes
        hashes = calculate_data_hashes(data)
        result.update(hashes)

        # Run detection on stdin data
        from ..detect.scoring import analyze_heuristics
        from ..detect.signatures import YaraEngine
        from ..static.pe import analyze_pe
        from ..static.type_id import detect_file_type

        file_type = detect_file_type(Path("<stdin>"), data)
        pe_info = analyze_pe(data) if file_type.get("is_executable") else {}

        yara_engine = YaraEngine()
        yara_matches = yara_engine.scan_data(data)
        heuristic_findings = analyze_heuristics(data, file_type, pe_info)

        result["hits"] = yara_matches + heuristic_findings
        result["clean"] = len(result["hits"]) == 0
        result["file_type"] = file_type
        result["pe_info"] = pe_info

        results = [result]

    elif path is not None:
        if not path.exists():
            typer.echo(f"Error: path does not exist: {path}", err=True)
            raise typer.Exit(2)

        results = engine.scan_path(path, recursive)
    else:
        typer.echo("Error: provide --stdin or --path/-p", err=True)
        raise typer.Exit(2)

    # Render
    if output.lower() == "json":
        typer.echo(json.dumps(results, indent=2))
    else:
        detections = 0
        for r in results:
            tgt = r["target"]
            if r.get("error") is not None:
                typer.echo(f"[SKIPPED] {tgt}: {r['error']}")
                continue

            file_type = r.get("mime_type", "unknown")
            if r["clean"]:
                typer.echo(f"[CLEAN] {tgt} ({file_type}): {r['size']} bytes")
            else:
                detections += 1
                rules = ", ".join(h["rule"] for h in r["hits"])
                typer.echo(f"[DETECTED] {tgt} ({file_type}) -> {rules}")

        if detections:
            typer.echo(f"\nSummary: {detections} target(s) detected.")
        else:
            typer.echo("\nSummary: no detections")

    # Exit code
    if any(not r.get("clean", True) for r in results):
        raise typer.Exit(code=1)

    raise typer.Exit(code=0)


__all__ = ["app", "scan"]

# Force command registration
if __name__ != "__main__":
    # This ensures the scan command is registered when imported
    pass
