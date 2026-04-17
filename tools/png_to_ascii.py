#!/usr/bin/env python3
"""
Convert ``assets/torbunny.png`` to ASCII and optionally write ``assets/banner_logo.txt``.

Usage:
  python tools/png_to_ascii.py              # print to stdout
  python tools/png_to_ascii.py --write      # update assets/banner_logo.txt
  python tools/png_to_ascii.py path/to.png --width 80
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from banner import _DEFAULT_PNG, png_to_ascii  # noqa: E402


def main() -> None:
    p = argparse.ArgumentParser(description="PNG → ASCII for torbunny banner")
    p.add_argument(
        "image",
        nargs="?",
        type=Path,
        default=_DEFAULT_PNG,
        help=f"Input PNG (default: {_DEFAULT_PNG.name})",
    )
    p.add_argument("--width", type=int, default=72, help="ASCII width in columns")
    p.add_argument(
        "--write",
        action="store_true",
        help=f"Write to {_ROOT / 'assets' / 'banner_logo.txt'}",
    )
    args = p.parse_args()

    if not args.image.is_file():
        print(f"Missing image: {args.image}", file=sys.stderr)
        sys.exit(1)

    art = png_to_ascii(args.image, width=args.width)
    print(art)

    if args.write:
        out = _ROOT / "assets" / "banner_logo.txt"
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(art + "\n", encoding="utf-8")
        print(f"\nWrote {out}", file=sys.stderr)


if __name__ == "__main__":
    main()
