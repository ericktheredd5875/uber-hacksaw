from __future__ import annotations

import hashlib
import json
import mimetypes
import zipfile
from datetime import datetime
from pathlib import Path

import typer
from rich.console import Console

app = typer.Typer(no_args_is_help=True, add_completion=False)
console = Console()

ROOT = Path(__file__).resolve().parents[1]
DATASETS = ROOT / "datasets"
EICAR_DIR = DATASETS / "eicar"
BENIGN_DIR = DATASETS / "benign" / "text"
MANIFEST = DATASETS / "manifest.json"


def sha256_of(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


@app.command()
def init():
    """Create datasets folder structure."""
    for d in [EICAR_DIR, BENIGN_DIR]:
        d.mkdir(parents=True, exist_ok=True)

    (DATASETS / "README.md").write_text(
        "# Malware-Scanner Test Corpus\n\n"
        "- **eicar/**: canonical harmless AV test files\n"
        "- **benign/**: non-malicious files for baseline scans\n"
        "- **manifest.json**: auto-generated indexes with hashes and labels\n"
    )

    console.print("[green]Dataset structure initialized successfully.[/green]")


@app.command()
def add_eicar():
    """Generate EICAR samples (plain, zip, double-zip) without pasting the literal string here."""
    # Build the canonical 68-byte string from parts to avoid AV trip in logs/chat
    parts = [
        "X5O!P%@AP[4\\PZX54(P^)",
        "7CC)7}$",
        "EICAR-STANDARD-ANTIVIRUS-TEST-FILE!",
        "$H+H*",
    ]

    s = "".join(parts)
    EICAR_DIR.mkdir(parents=True, exist_ok=True)
    plain = EICAR_DIR / "eicar.com.txt"
    plain.write_bytes(s.encode("ascii"))
    console.print(f"[bold]{plain}[/bold]: [dim]{sha256_of(plain)}[/dim]")

    # Zip with eicar.com.txt at root
    z1 = EICAR_DIR / "eicar.zip"
    with zipfile.ZipFile(z1, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.write(plain, arcname="eicar.com.txt")

    # Double-Zip (Zip of the previous zip)
    z2 = EICAR_DIR / "eicar_double.zip"
    with zipfile.ZipFile(z2, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.write(z1, arcname="eicar.zip")

    console.print("[green]EICAR samples added successfully.[/green]")
    for p in [plain, z1, z2]:
        console.print(f"[bold]{p}[/bold]: [dim]{sha256_of(p)}[/dim]")


@app.command("gen-benign")
def gen_benign():
    """Generate small benign text-like files (txt/csv/json/xml/html)"""
    BENIGN_DIR.mkdir(parents=True, exist_ok=True)

    (BENIGN_DIR / "lorem-001.txt").write_text(
        "Lorem ipsum dolor sit amet, consectetur adipiscing elit.\n" * 50
    )
    (BENIGN_DIR / "sample.csv").write_text(
        "id,name,email\n1,Alice,alice@example.com\n2,Bob,bob@example.com\n"
    )
    (BENIGN_DIR / "sample.json").write_text(
        json.dumps({"users": [{"id": 1, "name": "Alice"}, {"id": 2, "name": "Bob"}]}, indent=2)
    )
    (BENIGN_DIR / "sample.xml").write_text(
        "<root>\n  <user id='1'>Alice</user>\n  <user id='2'>Bob</user>\n</root>\n"
    )
    (BENIGN_DIR / "sample.html").write_text(
        "<!doctype html><html><body><h1>Sample</h1><p>Hello.</p></body></html>"
    )
    console.print("[green]Benign text files generated.[/]")


def label_for(path: Path) -> str:
    if "eicar" in path.parts:
        return "test:eicar"

    return "benign"


@app.command()
def manifest():
    """Rebuild datasets/manifest.json with sha256, size, mime, label."""
    entries = []
    for p in DATASETS.rglob("*"):
        if p.is_file():
            rel = p.relative_to(DATASETS).as_posix()
            entries.append(
                {
                    "path": rel,
                    "size": p.stat().st_size,
                    "sha256": sha256_of(p),
                    "mime": mimetypes.guess_type(p.name)[0] or "application/octet-stream",
                    "label": label_for(p),
                }
            )

    out = {
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "entries": sorted(entries, key=lambda e: e["path"]),
    }

    MANIFEST.write_text(json.dumps(out, indent=2))
    console.print(f"[green]Wrote {MANIFEST.relative_to(ROOT)} with {len(entries)} entries[/]")


if __name__ == "__main__":
    app()
