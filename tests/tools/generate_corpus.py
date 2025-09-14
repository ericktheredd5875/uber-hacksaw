from __future__ import annotations

import argparse
import sys
from pathlib import Path

from tests.utils.eicar import (
    generate_benign_files,
    stream_real_eicar_to_consumer,
    write_defanged_variants,
)


def main() -> int:
    ap = argparse.ArgumentParser(description="Generate EICAR/benign corpus files.")
    ap.add_argument("--root", default="tests/corpus", help="Output corpus directory.")
    ap.add_argument(
        "--also-stream-real",
        action="store_true",
        help="Streams real EICAR bytes to stdout (PIPE THIS; do not redirect to a file).",
    )
    args = ap.parse_args()

    root = Path(args.root)
    benign_dir = root / "benign"
    eicar_dir = root / "eicar"

    benign = list(generate_benign_files(benign_dir))
    eicars = list(write_defanged_variants(eicar_dir))

    print(f"[OK] wrote {len(benign)} benign files --> {benign_dir}", file=sys.stderr)
    for p in benign:
        print(f" - {p}", file=sys.stderr)

    print(
        f"[OK] wrote {len(eicars)} defanged EICAR files --> {eicar_dir}",
        file=sys.stderr,
    )
    for p in eicars:
        print(f" - {p}", file=sys.stderr)

    if args.also_stream_real:
        # IMPORTANT: don't write to files. This is a stream-only action for your scanner.
        # Usage example:
        #   python -m tests.tools.generate_corpus --also-stream-real | python -m uber_hacksaw.cli.scan --stdin

        # def __emit_to_stdout(b: bytes):
        #     import sys

        #     sys.stdout.buffer.write(b)
        #     sys.stdout.flush()

        # stream_real_eicar_to_consumer(__emit_to_stdout)
        from tests.utils.eicar import eicar_bytes_real

        sys.stdout.buffer.write(eicar_bytes_real())
        sys.stdout.flush()

        print(
            "[WARN] Streamed real EICAR bytes to stdout (PIPE THIS; do not redirect to a file).",
            file=sys.stderr,
        )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
