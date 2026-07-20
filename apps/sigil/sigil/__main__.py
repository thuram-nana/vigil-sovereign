"""`python -m sigil` entry point — delegates to the CLI (same as the installed `sigil` console command)."""
from .cli import main

if __name__ == "__main__":
    main()
