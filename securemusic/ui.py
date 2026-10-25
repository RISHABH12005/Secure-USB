"""Dark Tkinter interface for SecureUSB."""

from __future__ import annotations

import ctypes
import os
import queue
import threading
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox, ttk

from . import __version__
from .errors import (
    AuthenticationError,
    BackupError,
    DuplicateNameError,
    FileOperationError,
    InsufficientSpaceError,
    InvalidFilenameError,
    MediaError,
    PasswordPolicyError,
    SecureUSBError,
    UnknownFileError,
    VaultChangedError,
    VaultFormatError,
    VaultLockedError,
    VaultTooLargeError,
)
from .player import (
    CleanupReport,
    TempMediaManager,
    cleanup_stale_temp_dirs,
    is_audio,
    open_default,
    open_with,
)
from .vault import (
    MIN_PASSWORD_LENGTH,
    AddResult,
    DeleteResult,
    ExtractResult,
    VaultSession,
    cleanup_stale_payload_files,
)

APP_TITLE = "SecureUSB"

BG = "#10141b"
SURFACE = "#181e29"
SURFACE_ALT = "#232b3a"
BORDER = "#303a4d"
FG = "#e9eef8"
MUTED = "#9aa6bd"
ACCENT = "#6c9cff"
ACCENT_STRONG = "#97b8ff"
ACCENT_TEXT = "#08101f"
SUCCESS = "#57d7a5"
SUCCESS_BG = "#16342a"
DANGER = "#ff8282"
DANGER_BG = "#392128"
WARN = "#f5c66b"
WARN_BG = "#382f1f"

FONT = "Segoe UI"


# --------------------------------------------------------------------- dialogs


def _center_on_parent(window: tk.Toplevel, parent: tk.Misc) -> None:
    window.update_idletasks()
    width = window.winfo_width()
    height = window.winfo_height()
    px, py = parent.winfo_rootx(), parent.winfo_rooty()
    pw, ph = parent.winfo_width(), parent.winfo_height()
    x = px + max(0, (pw - width) // 2)
    y = py + max(0, (ph - height) // 3)
    window.geometry(f"+{x}+{y}")


def _dark_entry(parent: tk.Misc, *, show: str | None = None) -> tk.Entry:
    return tk.Entry(
        parent,
        bg=SURFACE_ALT,
        fg=FG,
        insertbackground=FG,
        relief="flat",
        highlightthickness=1,
        highlightbackground=BORDER,
        highlightcolor=ACCENT,
        font=(FONT, 11),
        show=show or "",
        width=40,
    )


class PasswordDialog(tk.Toplevel):
    """Modal password prompt. Returns a string in ``result`` or None."""

    def __init__(
        self,
        parent: tk.Misc,
        *,
        title: str,
        prompt: str,
        confirm: bool = False,
        min_length: int | None = None,
    ) -> None:
        super().__init__(parent)
        self.result: str | None = None
        self._min_length = min_length
        self.configure(bg=BG)
        self.title(title)
        self.resizable(False, False)
        self.transient(parent)
        self.protocol("WM_DELETE_WINDOW", self._cancel)

        frame = tk.Frame(self, bg=BG, padx=24, pady=22)
        frame.pack(fill="both", expand=True)

        tk.Label(
            frame, text=title, bg=BG, fg=FG, font=(FONT, 13, "bold")
        ).pack(anchor="w")
        tk.Label(
            frame,
            text=prompt,
            bg=BG,
            fg=MUTED,
            wraplength=400,
            justify="left",
            font=(FONT, 9),
        ).pack(anchor="w", pady=(6, 14))

        tk.Label(
            frame, text="PASSWORD", bg=BG, fg=MUTED, font=(FONT, 8, "bold")
        ).pack(anchor="w")
        self._password = _dark_entry(frame, show="*")
        self._password.pack(fill="x", pady=(4, 10))

        self._confirmation: tk.Entry | None = None
        if confirm:
            tk.Label(
                frame,
                text="CONFIRM PASSWORD",
                bg=BG,
                fg=MUTED,
                font=(FONT, 8, "bold"),
            ).pack(anchor="w")
            self._confirmation = _dark_entry(frame, show="*")
            self._confirmation.pack(fill="x", pady=(4, 10))

        if min_length:
            tk.Label(
                frame,
                text=(
                    f"Use at least {min_length} characters. A long, unique passphrase "
                    "is stronger than a short password."
                ),
                bg=BG,
                fg=MUTED,
                wraplength=400,
                justify="left",
                font=(FONT, 8),
            ).pack(anchor="w")

        self._error = tk.Label(
            frame,
            text="",
            bg=BG,
            fg=DANGER,
            wraplength=400,
            justify="left",
            font=(FONT, 9),
        )
        self._error.pack(anchor="w", pady=(8, 0))

        buttons = tk.Frame(frame, bg=BG)
        buttons.pack(fill="x", pady=(16, 0))
        ttk.Button(
            buttons, text="Cancel", style="Ghost.TButton", command=self._cancel
        ).pack(side="right")
        ttk.Button(
            buttons, text="Continue", style="Accent.TButton", command=self._submit
        ).pack(side="right", padx=(0, 8))

        self.bind("<Return>", lambda _event: self._submit())
        self.bind("<Escape>", lambda _event: self._cancel())
        self._center(parent)
        self._password.focus_set()
        try:
            self.grab_set()
        except tk.TclError:
            pass
        parent.wait_window(self)

    def _center(self, parent: tk.Misc) -> None:
        # Delay centering until the window has its natural size.
        self.update_idletasks()
        _center_on_parent(self, parent)

    def _clear(self) -> None:
        self._password.delete(0, "end")
        if self._confirmation is not None:
            self._confirmation.delete(0, "end")

    def _cancel(self) -> None:
        self._clear()
        self.result = None
        self.destroy()

    def _submit(self) -> None:
        password = self._password.get()
        if not password:
            self._error.configure(text="Enter a password.")
            return
        if self._min_length is not None and len(password) < self._min_length:
            self._error.configure(
                text=f"Use at least {self._min_length} characters."
            )
            return
        if self._confirmation is not None:
            if password != self._confirmation.get():
                self._error.configure(text="The passwords do not match.")
                return
        self._clear()
        self.result = password
        self.destroy()


class TextPromptDialog(tk.Toplevel):
    """Small modal single-line text prompt used for renaming."""

    def __init__(
        self,
        parent: tk.Misc,
        *,
        title: str,
        prompt: str,
        initial: str = "",
    ) -> None:
        super().__init__(parent)
        self.result: str | None = None
        self.configure(bg=BG)
        self.title(title)
        self.resizable(False, False)
        self.transient(parent)
        self.protocol("WM_DELETE_WINDOW", self._cancel)

        frame = tk.Frame(self, bg=BG, padx=24, pady=22)
        frame.pack(fill="both", expand=True)
        tk.Label(frame, text=title, bg=BG, fg=FG, font=(FONT, 13, "bold")).pack(
            anchor="w"
        )
        tk.Label(
            frame,
            text=prompt,
            bg=BG,
            fg=MUTED,
            wraplength=420,
            justify="left",
            font=(FONT, 9),
        ).pack(anchor="w", pady=(6, 14))
        self._entry = _dark_entry(frame)
        self._entry.insert(0, initial)
        self._entry.select_range(0, "end")
        self._entry.pack(fill="x")
        self._error = tk.Label(
            frame, text="", bg=BG, fg=DANGER, font=(FONT, 9), wraplength=420
        )
        self._error.pack(anchor="w", pady=(8, 0))

        buttons = tk.Frame(frame, bg=BG)
        buttons.pack(fill="x", pady=(16, 0))
        ttk.Button(
            buttons, text="Cancel", style="Ghost.TButton", command=self._cancel
        ).pack(side="right")
        ttk.Button(
            buttons, text="Rename", style="Accent.TButton", command=self._submit
        ).pack(side="right", padx=(0, 8))

        self.bind("<Return>", lambda _event: self._submit())
        self.bind("<Escape>", lambda _event: self._cancel())
        self.update_idletasks()
        _center_on_parent(self, parent)
        self._entry.focus_set()
        try:
            self.grab_set()
        except tk.TclError:
            pass
        parent.wait_window(self)

    def _cancel(self) -> None:
        self.result = None
        self.destroy()

    def _submit(self) -> None:
        value = self._entry.get().strip()
        if not value:
            self._error.configure(text="Enter a filename.")
            return
        self.result = value
        self.destroy()


class BusyDialog(tk.Toplevel):
    """Non-cancellable progress window for slow KDF/IO work."""

    def __init__(self, parent: tk.Misc, message: str) -> None:
        super().__init__(parent)
        self.configure(bg=BG)
        self.title(APP_TITLE)
        self.resizable(False, False)
        self.transient(parent)
        self.protocol("WM_DELETE_WINDOW", lambda: None)

        frame = tk.Frame(self, bg=BG, padx=26, pady=22)
        frame.pack(fill="both", expand=True)
        tk.Label(
            frame,
            text=message,
            bg=BG,
            fg=FG,
            wraplength=360,
            justify="left",
            font=(FONT, 10),
        ).pack(anchor="w")
        self._bar = ttk.Progressbar(frame, mode="indeterminate", length=320)
        self._bar.pack(fill="x", pady=(16, 0))
        self._bar.start(14)

        self.update_idletasks()
        _center_on_parent(self, parent)
        try:
            self.grab_set()
        except tk.TclError:
            pass
        self.lift()

    def close(self) -> None:
        try:
            self._bar.stop()
        except tk.TclError:
            pass
        try:
            self.grab_release()
        except tk.TclError:
            pass
        self.destroy()


class SafetyDialog(tk.Toplevel):
    def __init__(self, parent: tk.Misc) -> None:
        super().__init__(parent)
        self.configure(bg=BG)
        self.title("Safety and limits")
        self.transient(parent)
        self.resizable(False, False)
        self.protocol("WM_DELETE_WINDOW", self.destroy)

        frame = tk.Frame(self, bg=BG, padx=24, pady=22)
        frame.pack(fill="both", expand=True)
        tk.Label(
            frame,
            text="Safety and limits",
            bg=BG,
            fg=FG,
            font=(FONT, 14, "bold"),
        ).pack(anchor="w")
        tk.Label(
            frame,
            text=(
                "SecureUSB protects only the files stored inside its encrypted "
                "vault file. Read this before relying on it."
            ),
            bg=BG,
            fg=MUTED,
            wraplength=540,
            justify="left",
            font=(FONT, 9),
        ).pack(anchor="w", pady=(6, 12))

        text_frame = tk.Frame(frame, bg=SURFACE)
        text_frame.pack(fill="both", expand=True)
        text_frame.columnconfigure(0, weight=1)
        text_frame.rowconfigure(0, weight=1)
        text = tk.Text(
            text_frame,
            bg=SURFACE,
            fg=FG,
            relief="flat",
            highlightthickness=1,
            highlightbackground=BORDER,
            wrap="word",
            width=66,
            height=18,
            padx=14,
            pady=14,
            font=(FONT, 9),
            cursor="arrow",
        )
        text.grid(row=0, column=0, sticky="nsew")
        safety_scroll = ttk.Scrollbar(
            text_frame, orient="vertical", command=text.yview
        )
        safety_scroll.grid(row=0, column=1, sticky="ns")
        text.configure(yscrollcommand=safety_scroll.set)
        text.insert(
            "1.0",
            "\n\n".join(
                [
                    "Formatting cannot be prevented. Nothing stored on the USB drive can stop "
                    "Windows, another computer, a phone, or a formatting tool from erasing or "
                    "reformatting the drive. Keep a separate backup.",
                    "Autorun is not reliable. This app does not rely on autorun and will not "
                    "start by itself on Windows, Android, iPhone, smart TVs, or car stereos. "
                    "Windows also blocks autorun from removable drives by default.",
                    "External players need a decrypted copy. When you play a song, the app "
                    "writes a temporary decrypted file to Windows' temp folder so the player "
                    "can read it. The app tries to delete it on lock, on exit, or with 'Clean "
                    "temp files', but Windows may keep it in use while the player is open. "
                    "Delete leftovers after closing the player.",
                    "Extracted files are not encrypted. Files you extract are ordinary copies "
                    "outside the vault. Protect or securely delete them when you are finished.",
                    "Originals are never moved or deleted. Adding a file reads it and stores an "
                    "encrypted copy in the vault. It does not move, modify, or delete your "
                    "original. Deleting from the vault does not touch files outside the vault.",
                    "Backups are encrypted. Before deleting files from the vault, the app "
                    "copies the current encrypted vault to a timestamped .backup file next to it "
                    "and verifies the copy. Adds and renames do not create automatic backups. "
                    "Manual Backup now remains available. Backups need the same password.",
                    "Password loss is permanent. There is no recovery key, and no one can "
                    "decrypt the vault without the password. Keep an offline copy of the password.",
                    "Cannot distinguish wrong password from damage. AES-GCM reports the same "
                    "authentication failure for an incorrect password and for modified ciphertext. "
                    "If the password is definitely correct, restore a backup.",
                ]
            ),
        )
        text.configure(state="disabled")
        ttk.Button(
            frame, text="Close", style="Accent.TButton", command=self.destroy
        ).pack(anchor="e", pady=(14, 0))

        self.update_idletasks()
        _center_on_parent(self, parent)
        try:
            self.grab_set()
        except tk.TclError:
            pass


# ------------------------------------------------------------------------- app


class SecureMusicApp:
    def __init__(self, root: tk.Tk) -> None:
        self.root = root
        self.session: VaultSession | None = None
        self.media: TempMediaManager | None = None
        self._busy = False
        self._iid_to_name: dict[str, str] = {}
        self._playback_warned = False
        self._last_dir = Path.home()

        self._status_var = tk.StringVar(
            value="Create a new vault or open an existing one."
        )
        self._vault_var = tk.StringVar(value="No vault open")
        self._count_var = tk.StringVar(value="0 files")
        self._selection_var = tk.StringVar(value="Nothing selected")
        self._song_var = tk.StringVar(value="Select one song in the list")

        root.title(f"{APP_TITLE} {__version__}")
        root.configure(bg=BG)
        _configure_theme(root)

        self._build()
        self._sync_ui()
        self._fit_window()
        root.minsize(940, 640)
        root.protocol("WM_DELETE_WINDOW", self.on_close)
        root.bind("<Control-n>", lambda _event: self.create_vault())
        root.bind("<Control-o>", lambda _event: self.open_vault())
        root.bind("<Control-l>", lambda _event: self.lock_vault())
        root.after(1200, self._cleanup_old_temp_dirs)

    # ---------------------------------------------------------------- building

    def _fit_window(self) -> None:
        """Size the window for the display and its DPI scaling."""
        self.root.update_idletasks()
        scaling = float(self.root.tk.call("tk", "scaling"))
        screen_w = self.root.winfo_screenwidth()
        screen_h = self.root.winfo_screenheight()
        available_w = max(800, screen_w - 80)
        available_h = max(600, screen_h - 100)
        required_w = self.root.winfo_reqwidth()
        required_h = self.root.winfo_reqheight()
        factor = min(
            1.0,
            max(0.75, (available_w - 32) / required_w),
            max(0.75, (available_h - 32) / required_h),
        )
        if factor < 0.999:
            self.root.tk.call("tk", "scaling", scaling * factor)
            self.root.update_idletasks()
            required_w = self.root.winfo_reqwidth()
            required_h = self.root.winfo_reqheight()
        width = min(max(required_w + 24, 1120), available_w)
        height = min(max(required_h + 24, 740), available_h)
        x = max(0, (screen_w - width) // 2)
        y = max(0, (screen_h - height) // 3)
        self.root.geometry(f"{width}x{height}+{x}+{y}")

    def _build(self) -> None:
        outer = tk.Frame(self.root, bg=BG, padx=22, pady=14)
        outer.pack(fill="both", expand=True)
        outer.columnconfigure(0, weight=1)
        outer.rowconfigure(2, weight=1)

        header = tk.Frame(outer, bg=BG)
        header.grid(row=0, column=0, sticky="ew")
        title_block = tk.Frame(header, bg=BG)
        title_block.pack(side="left")
        tk.Label(
            title_block, text=APP_TITLE, bg=BG, fg=FG, font=(FONT, 22, "bold")
        ).pack(anchor="w")
        tk.Label(
            title_block,
            text="AES-256-GCM encrypted vault for music and personal files",
            bg=BG,
            fg=MUTED,
            font=(FONT, 10),
        ).pack(anchor="w", pady=(2, 0))
        ttk.Button(
            header,
            text="Safety & limits",
            style="Ghost.TButton",
            command=lambda: SafetyDialog(self.root),
        ).pack(side="right")

        vault_shell, vault_card = _card(outer)
        vault_shell.grid(row=1, column=0, sticky="ew", pady=(12, 10))

        vault_top = tk.Frame(vault_card, bg=SURFACE)
        vault_top.pack(fill="x")
        tk.Label(
            vault_top,
            text="VAULT",
            bg=SURFACE,
            fg=MUTED,
            font=(FONT, 8, "bold"),
        ).pack(side="left")
        self.state_pill = tk.Label(
            vault_top,
            text="LOCKED",
            bg=SURFACE_ALT,
            fg=MUTED,
            padx=10,
            pady=3,
            font=(FONT, 8, "bold"),
        )
        self.state_pill.pack(side="right")

        tk.Label(
            vault_card,
            textvariable=self._vault_var,
            bg=SURFACE,
            fg=FG,
            anchor="w",
            justify="left",
            wraplength=1000,
            font=(FONT, 10),
        ).pack(fill="x", pady=(6, 12))

        vault_buttons = tk.Frame(vault_card, bg=SURFACE)
        vault_buttons.pack(fill="x")
        self.btn_create = ttk.Button(
            vault_buttons,
            text="Create vault",
            style="Accent.TButton",
            command=self.create_vault,
        )
        self.btn_create.pack(side="left")
        self.btn_open = ttk.Button(
            vault_buttons, text="Open vault", command=self.open_vault
        )
        self.btn_open.pack(side="left", padx=(8, 0))
        self.btn_lock = ttk.Button(
            vault_buttons, text="Lock", style="Ghost.TButton", command=self.lock_vault
        )
        self.btn_lock.pack(side="left", padx=(8, 0))
        tk.Label(
            vault_buttons,
            text="Ctrl+N new  •  Ctrl+O open  •  Ctrl+L lock",
            bg=SURFACE,
            fg=MUTED,
            font=(FONT, 8),
        ).pack(side="right")

        body = tk.Frame(outer, bg=BG)
        body.grid(row=2, column=0, sticky="nsew")
        body.columnconfigure(0, weight=1)
        body.columnconfigure(1, weight=0, minsize=340)
        body.rowconfigure(0, weight=1)

        files_shell, files_card = _card(body)
        files_shell.grid(row=0, column=0, sticky="nsew", padx=(0, 12))
        files_card.columnconfigure(0, weight=1)
        files_card.rowconfigure(2, weight=1)

        files_top = tk.Frame(files_card, bg=SURFACE)
        files_top.grid(row=0, column=0, sticky="ew")
        tk.Label(
            files_top,
            text="Encrypted files",
            bg=SURFACE,
            fg=FG,
            font=(FONT, 11, "bold"),
        ).pack(side="left")
        tk.Label(
            files_top,
            textvariable=self._count_var,
            bg=SURFACE,
            fg=MUTED,
            font=(FONT, 9),
        ).pack(side="right")
        tk.Label(
            files_card,
            textvariable=self._selection_var,
            bg=SURFACE,
            fg=MUTED,
            anchor="w",
            font=(FONT, 8),
        ).grid(row=1, column=0, sticky="ew", pady=(2, 8))

        tree_frame = tk.Frame(files_card, bg=SURFACE)
        tree_frame.grid(row=2, column=0, sticky="nsew")
        tree_frame.columnconfigure(0, weight=1)
        tree_frame.rowconfigure(0, weight=1)

        self.tree = ttk.Treeview(
            tree_frame,
            columns=("name", "size", "type"),
            show="headings",
            selectmode="extended",
            height=8,
        )
        self.tree.heading("name", text="File name")
        self.tree.heading("size", text="Size")
        self.tree.heading("type", text="Type")
        self.tree.column("name", width=440, minwidth=200, anchor="w")
        self.tree.column("size", width=100, minwidth=80, anchor="e")
        self.tree.column("type", width=120, minwidth=90, anchor="w")
        self.tree.tag_configure("audio", foreground=ACCENT_STRONG)
        self.tree.grid(row=0, column=0, sticky="nsew")
        scrollbar = ttk.Scrollbar(
            tree_frame, orient="vertical", command=self.tree.yview
        )
        scrollbar.grid(row=0, column=1, sticky="ns")
        self.tree.configure(yscrollcommand=scrollbar.set)
        self.tree.bind("<<TreeviewSelect>>", self._on_tree_select)
        self.tree.bind("<Double-1>", self._on_tree_double_click)

        side = tk.Frame(body, bg=BG)
        side.grid(row=0, column=1, sticky="nsew")
        side.columnconfigure(0, weight=1)

        player_shell, player_card = _card(side)
        player_shell.grid(row=0, column=0, sticky="ew")
        tk.Label(
            player_card,
            text="Music player",
            bg=SURFACE,
            fg=FG,
            font=(FONT, 11, "bold"),
        ).pack(anchor="w")
        tk.Label(
            player_card,
            textvariable=self._song_var,
            bg=SURFACE,
            fg=ACCENT_STRONG,
            wraplength=280,
            justify="left",
            font=(FONT, 10, "bold"),
        ).pack(anchor="w", pady=(6, 2))
        tk.Label(
            player_card,
            text=(
                "Playing uses a temporary decrypted copy because external players "
                "cannot read the vault. The copy is deleted when you lock or exit, "
                "or with the button below, when Windows allows it."
            ),
            bg=SURFACE,
            fg=MUTED,
            wraplength=280,
            justify="left",
            font=(FONT, 8),
        ).pack(anchor="w", pady=(0, 10))

        player_row = tk.Frame(player_card, bg=SURFACE)
        player_row.pack(fill="x")
        self.btn_play = ttk.Button(
            player_row,
            text="Play",
            style="Accent.TButton",
            command=self.play_selected,
        )
        self.btn_play.pack(side="left")
        self.btn_play_with = ttk.Button(
            player_row, text="Play with...", command=self.play_with_selected
        )
        self.btn_play_with.pack(side="left", padx=(8, 0))
        self.btn_clean = ttk.Button(
            player_card,
            text="Clean temp files",
            style="Ghost.TButton",
            command=self.clean_temp_files,
        )
        self.btn_clean.pack(anchor="w", pady=(10, 0))

        notes_shell, notes_card = _card(side)
        notes_shell.grid(row=1, column=0, sticky="new", pady=(8, 0))
        tk.Label(
            notes_card,
            text="Reminders",
            bg=SURFACE,
            fg=FG,
            font=(FONT, 11, "bold"),
        ).pack(anchor="w")
        for note in (
            "Formatting the USB outside this app cannot be prevented.",
            "Autorun is not reliable; this app does not auto-start.",
            "Extracted copies are not encrypted.",
            "Losing the password means losing the vault.",
        ):
            tk.Label(
                notes_card,
                text="•  " + note,
                bg=SURFACE,
                fg=MUTED,
                wraplength=280,
                justify="left",
                anchor="w",
                font=(FONT, 8),
            ).pack(anchor="w", pady=(3, 0))

        actions = tk.Frame(outer, bg=BG)
        actions.grid(row=3, column=0, sticky="ew", pady=(10, 0))
        self.btn_add = ttk.Button(
            actions,
            text="Add files",
            style="Accent.TButton",
            command=self.add_files,
        )
        self.btn_add.pack(side="left")
        self.btn_extract = ttk.Button(
            actions, text="Extract selected", command=self.extract_selected
        )
        self.btn_extract.pack(side="left", padx=(8, 0))
        self.btn_rename = ttk.Button(
            actions, text="Rename", command=self.rename_selected
        )
        self.btn_rename.pack(side="left", padx=(8, 0))
        self.btn_delete = ttk.Button(
            actions,
            text="Delete from vault",
            style="Danger.TButton",
            command=self.delete_selected,
        )
        self.btn_delete.pack(side="left", padx=(8, 0))
        self.btn_backup = ttk.Button(
            actions,
            text="Backup now",
            style="Ghost.TButton",
            command=self.backup_now,
        )
        self.btn_backup.pack(side="left", padx=(16, 0))
        tk.Label(
            actions,
            text="Encrypted backups are made automatically before each change.",
            bg=BG,
            fg=MUTED,
            font=(FONT, 8),
        ).pack(side="right")

        status_shell = tk.Frame(
            outer,
            bg=SURFACE,
            highlightbackground=BORDER,
            highlightthickness=1,
        )
        status_shell.grid(row=4, column=0, sticky="ew", pady=(12, 0))
        self.status_label = tk.Label(
            status_shell,
            textvariable=self._status_var,
            bg=SURFACE,
            fg=MUTED,
            anchor="w",
            justify="left",
            padx=12,
            pady=8,
            font=(FONT, 9),
            wraplength=1040,
        )
        self.status_label.pack(fill="x")

        self._vault_action_buttons = [
            self.btn_add,
            self.btn_extract,
            self.btn_rename,
            self.btn_delete,
            self.btn_backup,
            self.btn_play,
            self.btn_play_with,
        ]

    # -------------------------------------------------------------- UI state

    def _sync_ui(self) -> None:
        unlocked = bool(self.session and self.session.unlocked)
        state = "normal" if unlocked else "disabled"
        for button in self._vault_action_buttons:
            button.configure(state=state)
        self.btn_lock.configure(state=state)
        self.btn_create.configure(state="disabled" if unlocked else "normal")
        self.btn_open.configure(state="disabled" if unlocked else "normal")

        media_pending = bool(self.media and self.media.pending)
        self.btn_clean.configure(
            state="normal" if (unlocked or media_pending) else "disabled"
        )

        if unlocked and self.session is not None:
            self.state_pill.configure(text="UNLOCKED", bg=SUCCESS_BG, fg=SUCCESS)
            self._vault_var.set(str(self.session.path))
        else:
            self.state_pill.configure(text="LOCKED", bg=SURFACE_ALT, fg=MUTED)
            self._vault_var.set("No vault open")
            self._song_var.set("Select one song in the list")

        if not unlocked:
            self._selection_var.set("Nothing selected")

    def _set_status(self, message: str, kind: str = "info") -> None:
        self._status_var.set(message)
        colors = {
            "info": MUTED,
            "success": SUCCESS,
            "warn": WARN,
            "error": DANGER,
        }
        self.status_label.configure(fg=colors.get(kind, MUTED))

    def _refresh_files(self) -> None:
        previously_selected = set(self._selected_names())
        for iid in self.tree.get_children():
            self.tree.delete(iid)
        self._iid_to_name.clear()
        if not self.session or not self.session.unlocked:
            self._count_var.set("0 files")
            self._selection_var.set("Nothing selected")
            return
        entries = self.session.list_files()
        for index, entry in enumerate(entries):
            iid = f"row{index}"
            suffix = Path(entry.name).suffix.lower()
            if is_audio(entry.name):
                type_label = f"{suffix[1:].upper()} audio" if suffix else "audio"
            elif suffix:
                type_label = suffix[1:].upper()
            else:
                type_label = "file"
            self.tree.insert(
                "",
                "end",
                iid=iid,
                values=(entry.name, _fmt_size(entry.size), type_label),
                tags=("audio",) if is_audio(entry.name) else (),
            )
            self._iid_to_name[iid] = entry.name
        if previously_selected:
            for iid, name in self._iid_to_name.items():
                if name in previously_selected:
                    self.tree.selection_add(iid)
        count = len(entries)
        self._count_var.set(f"{count} file{'s' if count != 1 else ''}")
        self._update_selection_info()

    def _selected_names(self) -> list[str]:
        return [
            self._iid_to_name[iid]
            for iid in self.tree.selection()
            if iid in self._iid_to_name
        ]

    def _update_selection_info(self) -> None:
        names = self._selected_names()
        if not names:
            self._selection_var.set("Nothing selected")
            self._song_var.set("Select one song in the list")
            return
        if len(names) == 1:
            self._selection_var.set(f"Selected: {names[0]}")
            if is_audio(names[0]):
                self._song_var.set(names[0])
            else:
                self._song_var.set("Selected file is not a recognised audio file")
        else:
            self._selection_var.set(f"{len(names)} files selected")
            self._song_var.set("Select exactly one song")

    def _on_tree_select(self, _event: tk.Event) -> None:
        self._update_selection_info()

    def _on_tree_double_click(self, _event: tk.Event) -> None:
        names = self._selected_names()
        if len(names) == 1 and is_audio(names[0]):
            self.play_selected()

    # --------------------------------------------------------------- helpers

    def _require_session(self) -> VaultSession | None:
        if self.session is None or not self.session.unlocked:
            messagebox.showinfo(
                APP_TITLE, "Create or unlock a vault first.", parent=self.root
            )
            return None
        return self.session

    def _run_task(self, message: str, work, on_success) -> None:
        if self._busy:
            return
        self._busy = True
        dialog = BusyDialog(self.root, message)
        results: queue.Queue = queue.Queue()

        def runner() -> None:
            try:
                results.put((True, work()))
            except BaseException as exc:  # noqa: BLE001 - reported in the UI thread
                results.put((False, exc))

        threading.Thread(target=runner, daemon=True).start()

        def poll() -> None:
            try:
                ok, payload = results.get_nowait()
            except queue.Empty:
                self.root.after(80, poll)
                return
            self._busy = False
            dialog.close()
            if ok:
                try:
                    on_success(payload)
                except Exception as exc:  # noqa: BLE001
                    self._handle_error(exc)
            else:
                self._handle_error(payload)

        self.root.after(80, poll)

    def _handle_error(self, exc: BaseException) -> None:
        short = "Operation failed."
        if isinstance(exc, AuthenticationError):
            messagebox_title = "Incorrect password or damaged vault"
            message = (
                "Authentication failed.\n\n"
                "The password is incorrect, or the encrypted vault data is damaged. "
                "AES-GCM cannot distinguish these two cases by design. Check the "
                "password, and if you are certain it is correct, restore an "
                "encrypted backup."
            )
            short = "Incorrect password or damaged vault."
        elif isinstance(exc, VaultFormatError):
            messagebox_title = "Vault cannot be opened"
            message = f"{exc}\n\nNo files were changed."
            short = "Invalid or damaged vault."
        elif isinstance(exc, VaultChangedError):
            messagebox_title = "Vault changed on disk"
            message = f"{exc}\n\nThe vault was locked for safety."
            short = "Vault changed on disk; locked."
            self._force_lock()
        elif isinstance(exc, VaultLockedError):
            messagebox_title = "Vault locked"
            message = "The vault is locked. Open it again before continuing."
            short = "Vault is locked."
        elif isinstance(exc, PasswordPolicyError):
            messagebox_title = "Password policy"
            message = str(exc)
            short = "Password does not meet the policy."
        elif isinstance(exc, InvalidFilenameError):
            messagebox_title = "Invalid filename"
            message = str(exc)
            short = "Invalid filename."
        elif isinstance(exc, DuplicateNameError):
            messagebox_title = "Duplicate name"
            message = str(exc)
            short = "Duplicate filename."
        elif isinstance(exc, UnknownFileError):
            messagebox_title = "File not found"
            message = str(exc)
            short = "File not found in vault."
        elif isinstance(exc, BackupError):
            messagebox_title = "Backup failed"
            message = f"{exc}\n\nNo changes were made."
            short = "Backup failed; no changes made."
        elif isinstance(exc, InsufficientSpaceError):
            messagebox_title = "Not enough space"
            message = f"{exc}\n\nNo changes were made."
            short = "Not enough free space."
        elif isinstance(exc, VaultTooLargeError):
            messagebox_title = "Vault size limit"
            message = str(exc)
            short = "Vault size limit reached."
        elif isinstance(exc, MediaError):
            messagebox_title = "Player problem"
            message = str(exc)
            short = "Could not open the song."
        elif isinstance(exc, FileOperationError):
            messagebox_title = "File operation failed"
            message = str(exc)
            short = "File operation failed."
        elif isinstance(exc, SecureUSBError):
            messagebox_title = "Operation failed"
            message = str(exc)
            short = "Operation failed."
        elif isinstance(exc, PermissionError):
            messagebox_title = "Permission denied"
            message = (
                f"Windows denied access to {exc.filename or 'the file'}.\n\n"
                "Close any program using it and check the folder permissions."
            )
            short = "Permission denied."
        elif isinstance(exc, OSError):
            messagebox_title = "File error"
            message = f"{exc}\n\nNo changes were made unless the operation reported success."
            short = "File error."
        else:
            messagebox_title = "Unexpected error"
            message = f"An unexpected error occurred:\n\n{type(exc).__name__}: {exc}"
            short = "Unexpected error."

        messagebox.showerror(messagebox_title, message, parent=self.root)
        self._set_status(short, "error")

    def _force_lock(self) -> None:
        self._cleanup_media()
        if self.session is not None:
            self.session.lock()
        self.session = None
        self._refresh_files()
        self._sync_ui()

    # -------------------------------------------------------------- commands

    def create_vault(self) -> None:
        if self._busy or self.session is not None:
            return
        path = filedialog.asksaveasfilename(
            parent=self.root,
            title="Create an encrypted vault",
            initialdir=str(self._last_dir),
            initialfile="music-vault.smusb",
            defaultextension=".smusb",
            filetypes=[("SecureMusic vault", "*.smusb"), ("All files", "*.*")],
        )
        if not path:
            return
        destination = Path(path)
        self._last_dir = destination.parent
        if destination.exists():
            messagebox.showerror(
                APP_TITLE,
                "That file already exists. This app never overwrites an existing "
                "file when creating a vault. Choose a new name.",
                parent=self.root,
            )
            return

        dialog = PasswordDialog(
            self.root,
            title="Set the vault password",
            prompt=(
                "This password encrypts every file in the vault. It is never stored. "
                "If you lose it, the vault cannot be recovered."
            ),
            confirm=True,
            min_length=MIN_PASSWORD_LENGTH,
        )
        password = dialog.result
        if password is None:
            return
        self._run_task(
            "Creating the encrypted vault...",
            lambda: VaultSession.create(destination, password),
            lambda session: self._after_unlock(session, created=True),
        )

    def open_vault(self) -> None:
        if self._busy or self.session is not None:
            return
        path = filedialog.askopenfilename(
            parent=self.root,
            title="Open a SecureMusic vault",
            initialdir=str(self._last_dir),
            filetypes=[
                ("SecureMusic vault", "*.smusb"),
                ("All files", "*.*"),
            ],
        )
        if not path:
            return
        source = Path(path)
        self._last_dir = source.parent
        dialog = PasswordDialog(
            self.root,
            title="Unlock vault",
            prompt=f"Enter the password for {source.name}.",
        )
        password = dialog.result
        if password is None:
            return
        self._run_task(
            "Unlocking the vault...",
            lambda: VaultSession.unlock(source, password),
            lambda session: self._after_unlock(session, created=False),
        )

    def _after_unlock(self, session: VaultSession, *, created: bool) -> None:
        self.session = session
        self._refresh_files()
        self._sync_ui()
        count = len(session.list_files())
        if created:
            self._set_status(
                "Vault created and unlocked. Add songs or files to encrypt them.",
                "success",
            )
        else:
            self._set_status(
                f"Vault unlocked. {count} encrypted file"
                f"{'s' if count != 1 else ''} available.",
                "success",
            )

    def lock_vault(self) -> None:
        if self._busy:
            return
        report = self._cleanup_media()
        if self.session is not None:
            self.session.lock()
            self.session = None
        self._refresh_files()
        self._sync_ui()
        if report and report.failed:
            self._set_status(
                f"Vault locked. {len(report.failed)} temporary file(s) are still "
                "in use and will be retried.",
                "warn",
            )
            messagebox.showwarning(
                APP_TITLE,
                f"{len(report.failed)} decrypted temporary file(s) could not be "
                "deleted because a media player is still using them.\n\n"
                "Close the player and use 'Delete temp copies' to retry. They are in:\n"
                f"{self.media.directory if self.media else 'the temporary folder'}",
                parent=self.root,
            )
        else:
            self._set_status(
                "Vault locked. The password was cleared and decrypted temporary "
                "files were removed where possible.",
                "info",
            )

    def add_files(self) -> None:
        session = self._require_session()
        if session is None:
            return
        paths = filedialog.askopenfilenames(
            parent=self.root,
            title="Select files to encrypt",
            initialdir=str(self._last_dir),
        )
        if not paths:
            return
        self._last_dir = Path(paths[0]).parent
        self._run_task(
            f"Encrypting {len(paths)} file(s) and creating an encrypted backup...",
            lambda: session.add_files(paths),
            self._after_add,
        )

    def _after_add(self, result: AddResult) -> None:
        self._refresh_files()
        if not result.added:
            skipped = "; ".join(
                f"{Path(path).name}: {reason}" for path, reason in result.skipped[:5]
            )
            self._set_status("No files were added.", "warn")
            messagebox.showwarning(
                APP_TITLE,
                "No files were added." + (f"\n\n{skipped}" if skipped else ""),
                parent=self.root,
            )
            return
        self._set_status(
            f"Added {len(result.added)} file(s). Encrypted backup created.", "success"
        )
        details = [f"Added {len(result.added)} file(s) to the encrypted vault."]
        if result.renamed:
            details.append(
                "Renamed to avoid collisions:\n" + _summarize_pairs(result.renamed)
            )
        if result.skipped:
            details.append(
                "Skipped:\n"
                + "\n".join(
                    f"{Path(path).name}: {reason}"
                    for path, reason in result.skipped[:5]
                )
            )
        if result.backup is not None:
            details.append(f"Encrypted backup: {result.backup.name}")
        if result.renamed or result.skipped:
            messagebox.showinfo(APP_TITLE, "\n\n".join(details), parent=self.root)

    def extract_selected(self) -> None:
        session = self._require_session()
        if session is None:
            return
        names = self._selected_names()
        if not names:
            messagebox.showinfo(
                APP_TITLE, "Select one or more files first.", parent=self.root
            )
            return
        folder = filedialog.askdirectory(
            parent=self.root,
            title="Choose a folder for decrypted copies",
            initialdir=str(self._last_dir),
        )
        if not folder:
            return
        destination = Path(folder)
        self._last_dir = destination
        try:
            conflicts = session.preview_extract_conflicts(names, destination)
        except SecureUSBError as exc:
            self._handle_error(exc)
            return

        overwrite = False
        if conflicts:
            answer = messagebox.askyesnocancel(
                APP_TITLE,
                f"{len(conflicts)} file(s) already exist in the destination.\n\n"
                "Yes: overwrite the existing files.\n"
                "No: keep the existing files and save numbered copies.\n"
                "Cancel: do nothing.",
                parent=self.root,
            )
            if answer is None:
                return
            overwrite = bool(answer)

        self._run_task(
            "Extracting decrypted copies...",
            lambda: session.extract(names, destination, overwrite=overwrite),
            lambda result: self._after_extract(result, destination),
        )

    def _after_extract(self, result: ExtractResult, destination: Path) -> None:
        self._set_status(
            "Extracted decrypted copies. These files are NOT protected by the vault.",
            "warn",
        )
        lines = [
            f"Extracted {len(result.written)} file(s) to:\n{destination}",
            "These copies are plain, unencrypted files. Anyone with access to the "
            "folder can read them. Protect or delete them when you are finished.",
        ]
        if result.renamed:
            lines.append(
                "Existing files were kept; numbered copies were created:\n"
                + _summarize_pairs(result.renamed)
            )
        messagebox.showwarning(APP_TITLE, "\n\n".join(lines), parent=self.root)

    def rename_selected(self) -> None:
        session = self._require_session()
        if session is None:
            return
        names = self._selected_names()
        if len(names) != 1:
            messagebox.showinfo(
                APP_TITLE, "Select exactly one file to rename.", parent=self.root
            )
            return
        current = names[0]
        dialog = TextPromptDialog(
            self.root,
            title="Rename encrypted file",
            prompt=f"Enter a new name for {current!r}.",
            initial=current,
        )
        new_name = dialog.result
        if new_name is None:
            return
        if new_name == current:
            return
        self._run_task(
            "Renaming and creating an encrypted backup...",
            lambda: session.rename_file(current, new_name),
            lambda backup: self._after_rename(current, new_name, backup),
        )

    def _after_rename(self, old: str, new: str, backup: Path | None) -> None:
        self._refresh_files()
        message = f"Renamed {old!r} to {new!r}."
        if backup is not None:
            message += f" Encrypted backup: {backup.name}"
        self._set_status(message, "success")

    def delete_selected(self) -> None:
        session = self._require_session()
        if session is None:
            return
        names = self._selected_names()
        if not names:
            messagebox.showinfo(
                APP_TITLE, "Select one or more files first.", parent=self.root
            )
            return
        preview = "\n".join(f"• {name}" for name in names[:6])
        if len(names) > 6:
            preview += f"\n...and {len(names) - 6} more"
        confirmed = messagebox.askyesno(
            APP_TITLE,
            f"Remove {len(names)} file(s) from the encrypted vault?\n\n{preview}\n\n"
            "An encrypted backup is created first. Files outside the vault, "
            "including your original songs, are not touched.",
            parent=self.root,
        )
        if not confirmed:
            return
        self._run_task(
            "Deleting from the vault and creating an encrypted backup...",
            lambda: session.delete_files(names),
            self._after_delete,
        )

    def _after_delete(self, result: DeleteResult) -> None:
        self._refresh_files()
        message = f"Removed {len(result.removed)} file(s) from the vault."
        if result.backup is not None:
            message += f" Encrypted backup: {result.backup.name}"
        self._set_status(message, "success")

    def backup_now(self) -> None:
        session = self._require_session()
        if session is None:
            return
        self._run_task(
            "Creating and verifying an encrypted backup...",
            session.backup_now,
            self._after_backup,
        )

    def _after_backup(self, backup: Path) -> None:
        self._set_status(f"Encrypted backup created and verified: {backup.name}", "success")

    # --------------------------------------------------------------- playback

    def play_selected(self) -> None:
        self._play(use_default=True)

    def play_with_selected(self) -> None:
        self._play(use_default=False)

    def _play(self, *, use_default: bool) -> None:
        session = self._require_session()
        if session is None:
            return
        names = self._selected_names()
        if len(names) != 1:
            messagebox.showinfo(
                APP_TITLE, "Select exactly one song in the list.", parent=self.root
            )
            return
        name = names[0]
        if not is_audio(name):
            if not messagebox.askyesno(
                APP_TITLE,
                f"{name!r} is not a recognised audio file. Try to open it anyway?",
                parent=self.root,
            ):
                return

        player_path: str | None = None
        if not use_default:
            player_path = filedialog.askopenfilename(
                parent=self.root,
                title="Choose a media player program",
                filetypes=[("Windows programs", "*.exe"), ("All files", "*.*")],
            )
            if not player_path:
                return

        if not self._playback_warned:
            proceed = messagebox.askyesno(
                APP_TITLE,
                "Playback needs a temporary DECRYPTED copy of the song in the "
                "Windows temp folder, because external media players cannot read "
                "the encrypted vault.\n\n"
                "The app tries to delete the copy when you lock the vault, close the "
                "app, or click 'Clean temp files'. It may remain while the player is "
                "still using it.\n\nContinue?",
                parent=self.root,
            )
            if not proceed:
                return
            self._playback_warned = True

        if self.media is None:
            self.media = TempMediaManager()
        media = self.media

        def work() -> Path:
            temp_path = media.materialize(session, name)
            if use_default:
                open_default(temp_path)
            else:
                assert player_path is not None
                open_with(temp_path, player_path)
            return temp_path

        self._run_task(
            "Preparing a temporary decrypted copy for playback...",
            work,
            lambda temp_path: self._after_play(name),
        )

    def _after_play(self, name: str) -> None:
        self._sync_ui()
        self._set_status(
            f"Opened {name!r} in an external player. A temporary decrypted copy "
            "exists until you lock, exit, or clean temp files.",
            "warn",
        )

    def clean_temp_files(self) -> None:
        report = self._cleanup_media()
        self._sync_ui()
        if report is None or report.removed == 0 and not report.failed:
            messagebox.showinfo(
                APP_TITLE, "There are no temporary decrypted files to clean.",
                parent=self.root,
            )
            return
        if report.failed:
            messagebox.showwarning(
                APP_TITLE,
                f"{len(report.failed)} temporary file(s) could not be deleted "
                "because Windows or a media player is still using them.\n\n"
                "Close the player and try again. They are in:\n"
                f"{self.media.directory if self.media else 'the temporary folder'}",
                parent=self.root,
            )
            self._set_status(
                f"{len(report.failed)} temporary file(s) are still in use.", "warn"
            )
        else:
            self._set_status(
                f"Removed {report.removed} temporary decrypted file(s).", "success"
            )

    def _cleanup_media(self) -> CleanupReport | None:
        if self.media is None:
            return None
        return self.media.cleanup()

    def _cleanup_old_temp_dirs(self) -> None:
        def work() -> None:
            try:
                cleanup_stale_temp_dirs(older_than_seconds=24 * 60 * 60)
            except OSError:
                pass
            try:
                cleanup_stale_payload_files(older_than_seconds=24 * 60 * 60)
            except OSError:
                pass

        threading.Thread(target=work, daemon=True).start()

    # ----------------------------------------------------------------- safety

    def show_safety(self) -> None:
        SafetyDialog(self.root)

    def on_close(self) -> None:
        if self._busy:
            self.root.bell()
            return
        if self.session is not None:
            confirmed = messagebox.askyesno(
                APP_TITLE,
                "Lock the vault and exit?\n\nTemporary decrypted copies will be "
                "deleted where Windows allows.",
                parent=self.root,
            )
            if not confirmed:
                return
        report = self._cleanup_media()
        if self.session is not None:
            self.session.lock()
            self.session = None
        if report is not None and report.failed:
            messagebox.showwarning(
                APP_TITLE,
                f"{len(report.failed)} temporary decrypted file(s) could not be "
                "deleted because Windows or a media player is still using them.\n\n"
                "They are in:\n"
                f"{self.media.directory if self.media else 'the temporary folder'}\n\n"
                "Delete them after closing the player.",
                parent=self.root,
            )
        self.root.destroy()


# ------------------------------------------------------------------ utilities


def _card(parent: tk.Misc) -> tuple[tk.Frame, tk.Frame]:
    shell = tk.Frame(
        parent,
        bg=SURFACE,
        highlightbackground=BORDER,
        highlightthickness=1,
        bd=0,
    )
    inner = tk.Frame(shell, bg=SURFACE)
    inner.pack(fill="both", expand=True, padx=16, pady=14)
    return shell, inner


def _fmt_size(value: int) -> str:
    if value < 1024:
        return f"{value} B"
    if value < 1024**2:
        return f"{value / 1024:.1f} KB"
    if value < 1024**3:
        return f"{value / 1024**2:.1f} MB"
    return f"{value / 1024**3:.2f} GB"


def _summarize_pairs(pairs: list[tuple[str, str]], limit: int = 5) -> str:
    lines = [f"{old}  ->  {new}" for old, new in pairs[:limit]]
    if len(pairs) > limit:
        lines.append(f"...and {len(pairs) - limit} more")
    return "\n".join(lines)


def _configure_theme(root: tk.Tk) -> None:
    style = ttk.Style(root)
    try:
        style.theme_use("clam")
    except tk.TclError:
        pass

    style.configure(
        ".",
        background=BG,
        foreground=FG,
        fieldbackground=SURFACE_ALT,
        bordercolor=BORDER,
        darkcolor=SURFACE,
        lightcolor=SURFACE,
        troughcolor=SURFACE_ALT,
        focuscolor=ACCENT,
        font=(FONT, 10),
    )
    style.configure("TFrame", background=BG)
    style.configure("TLabel", background=BG, foreground=FG)
    style.configure("TSeparator", background=BORDER)
    style.configure("TCheckbutton", background=SURFACE, foreground=FG)
    style.map(
        "TCheckbutton",
        background=[("active", SURFACE)],
        foreground=[("disabled", MUTED)],
    )

    style.configure(
        "TButton",
        background=SURFACE_ALT,
        foreground=FG,
        padding=(13, 7),
        borderwidth=0,
        relief="flat",
        focusthickness=0,
        font=(FONT, 9),
    )
    style.map(
        "TButton",
        background=[("active", BORDER), ("pressed", BORDER), ("disabled", SURFACE)],
        foreground=[("disabled", "#5c6578")],
    )

    style.configure(
        "Accent.TButton",
        background=ACCENT,
        foreground=ACCENT_TEXT,
        font=(FONT, 9, "bold"),
    )
    style.map(
        "Accent.TButton",
        background=[
            ("active", ACCENT_STRONG),
            ("pressed", ACCENT_STRONG),
            ("disabled", SURFACE_ALT),
        ],
        foreground=[("disabled", "#68718a")],
    )

    style.configure(
        "Ghost.TButton",
        background=SURFACE,
        foreground=MUTED,
        padding=(12, 7),
    )
    style.map(
        "Ghost.TButton",
        background=[("active", SURFACE_ALT), ("pressed", SURFACE_ALT)],
        foreground=[("active", FG), ("disabled", "#5c6578")],
    )

    style.configure(
        "Danger.TButton",
        background=DANGER_BG,
        foreground=DANGER,
        font=(FONT, 9, "bold"),
    )
    style.map(
        "Danger.TButton",
        background=[("active", "#4a2932"), ("pressed", "#4a2932"), ("disabled", SURFACE)],
        foreground=[("active", "#ffa0a0"), ("disabled", "#6a5a60")],
    )

    style.configure(
        "Treeview",
        background=SURFACE,
        fieldbackground=SURFACE,
        foreground=FG,
        borderwidth=0,
        rowheight=27,
        font=(FONT, 9),
    )
    style.configure(
        "Treeview.Heading",
        background=SURFACE_ALT,
        foreground=MUTED,
        relief="flat",
        borderwidth=0,
        padding=(8, 7),
        font=(FONT, 8, "bold"),
    )
    style.map(
        "Treeview",
        background=[("selected", "#2b4d8f")],
        foreground=[("selected", "#ffffff")],
    )
    style.map(
        "Treeview.Heading",
        background=[("active", BORDER)],
        foreground=[("active", FG)],
    )

    style.configure(
        "TEntry",
        fieldbackground=SURFACE_ALT,
        foreground=FG,
        insertcolor=FG,
        bordercolor=BORDER,
        lightcolor=BORDER,
        darkcolor=BORDER,
        padding=6,
    )

    style.configure(
        "TScrollbar",
        background=SURFACE_ALT,
        troughcolor=SURFACE,
        bordercolor=SURFACE,
        arrowcolor=MUTED,
    )
    style.map("TScrollbar", background=[("active", BORDER)])

    style.configure(
        "Horizontal.TProgressbar",
        background=ACCENT,
        troughcolor=SURFACE_ALT,
        bordercolor=SURFACE_ALT,
        lightcolor=ACCENT,
        darkcolor=ACCENT,
    )

    style.configure("TSpinbox", fieldbackground=SURFACE_ALT, foreground=FG)


def _enable_dpi_awareness() -> None:
    if os.name != "nt":
        return
    try:
        ctypes.windll.shcore.SetProcessDpiAwareness(1)
    except Exception:  # noqa: BLE001 - best effort
        try:
            ctypes.windll.user32.SetProcessDPIAware()
        except Exception:  # noqa: BLE001
            pass


def main() -> None:
    _enable_dpi_awareness()
    root = tk.Tk()
    app = SecureMusicApp(root)
    root.iconname(APP_TITLE)
    root.mainloop()
    del app


if __name__ == "__main__":
    main()
