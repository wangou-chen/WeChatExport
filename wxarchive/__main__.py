"""允许 `python -m wxarchive ...`"""
import sys

from .cli import main

if __name__ == "__main__":
    sys.exit(main())
