#!/usr/bin/env python3
"""Screen a folder of dependencies before they are trusted.

This file is only the entry point. The engine lives in scripts/screening/:
see docs/CODE_README.md for what each module does.

    python3 scripts/screen.py <folder> [--ecosystem ...] [--report ...]
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from screening.cli import main  # noqa: E402

if __name__ == "__main__":
    sys.exit(main())
