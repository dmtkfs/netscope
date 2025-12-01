from __future__ import annotations

import sys
from pathlib import Path


def main_runner() -> None:
    # Resolve project root and src/ directory
    root = Path(__file__).resolve().parent
    src = root / "src"

    # Add src/ to sys.path for this process only
    if str(src) not in sys.path:
        sys.path.insert(0, str(src))

    # Import only after we've patched sys.path
    from netscope.main import main as netscope_main

    netscope_main()


if __name__ == "__main__":
    main_runner()
