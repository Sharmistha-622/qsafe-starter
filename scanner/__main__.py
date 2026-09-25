"""Allow python -m scanner <args> invocation."""
import sys
from scanner.cli import main

sys.exit(main())
