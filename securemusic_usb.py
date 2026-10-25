"""SecureUSB launcher.

Run with ``py securemusic_usb.py`` (or ``py -m securemusic``).
"""

from __future__ import annotations

import sys


def main() -> int:
    try:
        from securemusic.ui import main as run_app
    except ModuleNotFoundError as exc:
        missing = exc.name or ""
        if missing.startswith("cryptography"):
            print(
                "SecureUSB needs the 'cryptography' package.\n\n"
                "Install dependencies with:\n"
                "  py -m pip install -r requirements.txt\n\n"
                "Or use a virtual environment:\n"
                "  py -m venv .venv\n"
                "  .venv\\Scripts\\python -m pip install -r requirements.txt\n"
                "  .venv\\Scripts\\python securemusic_usb.py",
                file=sys.stderr,
            )
            return 1
        if missing == "tkinter":
            print(
                "Tkinter is not available in this Python installation.\n"
                "Reinstall Python from python.org and keep the Tcl/Tk option enabled.",
                file=sys.stderr,
            )
            return 1
        raise

    run_app()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
