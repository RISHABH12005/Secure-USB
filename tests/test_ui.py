from __future__ import annotations

import tempfile
import tkinter as tk
import unittest
from pathlib import Path

from securemusic.ui import SecureMusicApp
from securemusic.vault import VaultSession
from tests.support import PASSWORD, TEST_KDF


def _tk_available() -> bool:
    root = None
    try:
        root = tk.Tk()
        root.withdraw()
        root.update_idletasks()
        return True
    except (tk.TclError, RuntimeError, OSError):
        # Some hosted Windows runners ship a Python build whose Tcl/Tk runtime
        # cannot initialize. Skip only the UI smoke test in that environment;
        # the crypto, vault, and file-operation tests still run normally.
        return False
    finally:
        if root is not None:
            try:
                root.destroy()
            except tk.TclError:
                pass


TK_AVAILABLE = _tk_available()


@unittest.skipUnless(TK_AVAILABLE, "a graphical display is not available")
class UiSmokeTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory(prefix="securemusic-ui-test-")
        self.addCleanup(self._tmp.cleanup)
        self.tmp = Path(self._tmp.name)
        self.root = tk.Tk()
        self.root.withdraw()
        self.addCleanup(self._destroy_root)
        self.app = SecureMusicApp(self.root)
        self.root.update_idletasks()

    def _destroy_root(self) -> None:
        try:
            self.root.destroy()
        except tk.TclError:
            pass

    def test_theme_builds_and_unlock_add_lock_flow(self) -> None:
        self.assertEqual(self.app.state_pill.cget("text"), "LOCKED")
        self.assertEqual(str(self.app.btn_add.cget("state")), "disabled")

        vault_path = self.tmp / "ui.smusb"
        session = VaultSession.create(vault_path, PASSWORD, params=TEST_KDF)
        self.app._after_unlock(session, created=True)
        self.root.update_idletasks()

        self.assertEqual(self.app.state_pill.cget("text"), "UNLOCKED")
        self.assertEqual(str(self.app.btn_add.cget("state")), "normal")
        self.assertEqual(self.app.tree.get_children(), ())

        source = self.tmp / "song.mp3"
        source.write_bytes(b"fake audio bytes")
        session.add_files([source])
        self.app._refresh_files()
        self.root.update_idletasks()
        self.assertEqual(len(self.app.tree.get_children()), 1)
        self.assertEqual(self.app._count_var.get(), "1 file")

        self.app._force_lock()
        self.root.update_idletasks()
        self.assertEqual(self.app.state_pill.cget("text"), "LOCKED")
        self.assertIsNone(self.app.session)
        self.assertFalse(session.unlocked)
