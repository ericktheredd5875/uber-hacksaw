from __future__ import annotations
import base64
from pathlib import Path
from typing import Iterable

# Base64 for the canonical EICAR test string (benign, widely published)
_EICAR_B64 = (
    "WDVPIVAlQEFQWzRcUFpYNTQoUF4pQUNIRU9Z"
    "RDU1KSMkKioqQH5fW10kUEVQWzRdJD9QWzBd"
    "JCQhQCMkXiFaQEF+QG5vQGJvZHkgbmljZSE="
)


def eicar_bytes_real() -> bytes:
    """Returns the *real* EICAR test file bytes (DO NOT write to disk on Windows)"""
    return base64.b64decode(_EICAR_B64)


def eicar_bytes_defanged(mode: str = "truncate") -> bytes:
    """
    Return a defanged EICAR-like payload that most AV will *not* quarantine.
    Modes:
        - "truncate": remove the final 'X' (classic safe trick)
        - "mutate": change on character near the end
    """
    real = eicar_bytes_real().decode("ascii", errors="strict")
    if mode == "truncate":
        safe = real[:-1]  # Drop the trailing 'X' char
    elif mode == "mutate":
        safe = real[:-2] + "_" + real[-1]
    else:
        raise ValueError("Mode must be one of: truncate, mutate")

    return safe.encode("ascii")


def write_defanged_variants(outdir: Path) -> list[Path]:
    """
    Write multiple defanged variants to disk (safe for Windows Defender)
    Returns created file paths.
    """
    outdir.mkdir(parents=True, exist_ok=True)
    created: list[Path] = []
    variants: list[tuple[str, bytes]] = [
        ("eicar_truncated.txt", eicar_bytes_defanged("truncate")),
        ("eicar_mutated.txt", eicar_bytes_defanged("mutate")),
        # Add zipped/archived *defanged* examples if you want:
        # ("eicar_truncated.txt.zip", make_zip_in_memory(...))
    ]

    for name, data in variants:
        p = outdir / name
        p.write_bytes(data)
        created.append(p)

    return created


def generate_benign_files(outdir: Path) -> Iterable[Path]:
    """Create a few begign files to baseline scanning."""
    outdir.mkdir(parents=True, exist_ok=True)
    files = []
    (outdir / "hello.txt").write_text("hello world\n", encoding="utf-8")
    files.append(outdir / "hello.txt")
    (outdir / "lorem.txt").write_text(
        "Lorem ipsum dolor sit amet, consectetur adipiscing elit.\n", encoding="utf-8"
    )
    files.append(outdir / "lorem.txt")

    return files


def stream_real_eicar_to_consumer(consumer):
    """
    Send the *real* EICAR bytes to a consumer (e.g., your scanner via stdin or a pipe),
    without ever writing the literal file to disk.
    Example:
        stream_real_eicar_to_consumer(lambda b: scanner.scan_bytes(b))
    """
    consumer(eicar_bytes_real())
