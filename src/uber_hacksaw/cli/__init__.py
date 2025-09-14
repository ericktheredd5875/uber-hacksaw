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


def _detect_file_type(file_path: Path, data: bytes) -> str:
    """Detect file type using multiple methods."""
    # Try MIME type first
    mime_type, _ = mimetypes.guess_type(str(file_path))
    if mime_type:
        return mime_type

    # Fallback to content-based detection
    if data.startswith(b"\x7fELF"):
        return "application/x-executable"
    elif data.startswith(b"MZ"):
        return "application/x-msdownload"
    elif data.startswith(b"PK"):
        return "application/zip"
    elif data.startswith(b"%PDF"):
        return "application/pdf"
    elif data.startswith(b"<!DOCTYPE") or data.startswith(b"<html"):
        return "text/html"
    elif data.startswith(b"{") or data.startswith(b"["):
        return "application/json"
    elif data.startswith(b"<?xml"):
        return "text/xml"
    else:
        return "application/octet-stream"


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
    file_type = (
        _detect_file_type(file_path or Path(label), data)
        if file_path or label != "<stdin>"
        else "application/octet-stream"
    )

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

    results: list[dict[str, Any]] = []
    if stdin:
        data = sys.stdin.buffer.read()
        results = [_scan_bytes_obj("<stdin>", data)]
    elif path is not None:
        if not path.exists():
            typer.echo(f"Error: path does not exist: {path}", err=True)
            raise typer.Exit(2)
        results = _scan_path(path, recursive)
    else:
        typer.echo("Error: provide --stdin or --path/-p", err=True)

    # Render
    if output.lower() == "json":
        print(json.dumps(results, indent=2))
    else:
        detections = 0
        for r in results:
            tgt = r["target"]
            if "error" in r:
                print(f"[SKIPPED] {tgt}: {r['error']}")
                continue

            file_type = r.get("type", "unknown")
            if r["clean"]:
                print(f"[CLEAN] {tgt} ({file_type}): {r['size']} bytes")
            else:
                detections += 1
                rules = ", ".join(h["rule"] for h in r["hits"])
                print(f"[DETECTED] {tgt} ({file_type}) -> {rules}")

        if detections:
            print(f"\nSummary: {detections} target(s) detected.")
        else:
            print("\nSummary: no detections")

    # Exit code
    if any(not r.get("clean", True) for r in results):
        raise typer.Exit(code=1)

    raise typer.Exit(code=0)


__all__ = ["app", "scan"]

# Force command registration
if __name__ != "__main__":
    # This ensures the scan command is registered when imported
    pass
