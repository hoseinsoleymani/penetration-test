"""Allow python -m nextaudit to use the same entrypoint."""
from .cli import main

raise SystemExit(main())
