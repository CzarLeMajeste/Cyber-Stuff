#!/usr/bin/env python3
"""
gui.py – Minimal desktop GUI for CTF Session Logger.

Requires only the Python standard library (tkinter + subprocess).

Usage
-----
    python gui.py

The GUI wraps two tools in this repository:
  • session-recorder  (Rust CLI – build with `cargo build --release`)
  • dump2note.py      (Python script)
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import threading
from datetime import date as _date
from pathlib import Path
from tkinter import filedialog, scrolledtext
import tkinter as tk

# ── Repository paths ──────────────────────────────────────────────────────────

_REPO_ROOT  = Path(__file__).resolve().parent
_REC_LOCAL  = _REPO_ROOT / "session-recorder" / "target" / "release" / "session-recorder"
_DUMP2NOTE  = _REPO_ROOT / "dump2note.py"

def _find_recorder() -> str | None:
    """Return path to session-recorder binary, or None if not found."""
    if _REC_LOCAL.exists():
        return str(_REC_LOCAL)
    return shutil.which("session-recorder")

RECORDER = _find_recorder()

# ── Colour palette (Catppuccin Mocha-inspired) ────────────────────────────────

BG      = "#1e1e2e"   # base
BG2     = "#181825"   # crust (log area)
FG      = "#cdd6f4"   # text
MUTED   = "#6c7086"   # overlay 1
ACCENT  = "#89b4fa"   # blue
SUCCESS = "#a6e3a1"   # green
WARN    = "#fab387"   # peach
ERR     = "#f38ba8"   # red
BTN_BG  = "#313244"   # surface 0
BTN_ACT = "#45475a"   # surface 1
BORDER  = "#313244"

# ── Reusable widget helpers ───────────────────────────────────────────────────

def _entry(parent: tk.Widget, width: int = 14, **kw) -> tk.Entry:
    return tk.Entry(
        parent, width=width, bg=BTN_BG, fg=FG,
        insertbackground=FG, relief="flat",
        highlightthickness=1, highlightbackground=BORDER,
        **kw,
    )


def _btn(parent: tk.Widget, text: str, command, col: int = 0,
         row: int = 0, padx: int = 2, pady: int = 0) -> tk.Button:
    b = tk.Button(
        parent, text=text, command=command,
        bg=BTN_BG, fg=FG,
        activebackground=BTN_ACT, activeforeground=FG,
        relief="flat", padx=6, pady=3, cursor="hand2",
    )
    b.grid(row=row, column=col, padx=padx, pady=pady)
    return b


def _label(parent: tk.Widget, text: str, col: int = 0, row: int = 0,
           fg: str = FG, padx: int = 4) -> tk.Label:
    lbl = tk.Label(parent, text=text, bg=BG, fg=fg)
    lbl.grid(row=row, column=col, padx=padx, sticky="w")
    return lbl


def _frame(parent: tk.Widget, title: str) -> tk.LabelFrame:
    return tk.LabelFrame(
        parent, text=title, fg=ACCENT, bg=BG,
        relief="flat", bd=0,
        highlightthickness=1, highlightbackground=BORDER,
    )


def _check(parent: tk.Widget, text: str, variable: tk.BooleanVar,
           col: int = 0) -> tk.Checkbutton:
    cb = tk.Checkbutton(
        parent, text=text, variable=variable,
        bg=BG, fg=FG, selectcolor=BTN_BG,
        activebackground=BG, activeforeground=FG,
    )
    cb.grid(row=0, column=col, padx=3)
    return cb


# ── Main application ──────────────────────────────────────────────────────────

class App(tk.Tk):
    def __init__(self) -> None:
        super().__init__()
        self.title("CTF Session Logger")
        self.resizable(False, False)
        self.configure(bg=BG)
        self._build_ui()
        self._refresh_status()

    # ── UI construction ───────────────────────────────────────────────────────

    def _build_ui(self) -> None:
        P = dict(padx=8, pady=4)

        # ── Recorder panel ────────────────────────────────────────────────────
        rec = _frame(self, " Session Recorder ")
        rec.grid(row=0, column=0, sticky="ew", **P)

        # Status row
        sf = tk.Frame(rec, bg=BG)
        sf.grid(row=0, column=0, sticky="w", padx=6, pady=(6, 2))

        self._dot = tk.Label(sf, text="●", fg=MUTED, bg=BG, font=("", 14))
        self._dot.grid(row=0, column=0, padx=(0, 4))
        self._status_lbl = tk.Label(sf, text="Unknown", fg=FG, bg=BG)
        self._status_lbl.grid(row=0, column=1)
        _btn(sf, "⟳", self._refresh_status, col=2, padx=(10, 0))

        # Action buttons
        af = tk.Frame(rec, bg=BG)
        af.grid(row=1, column=0, sticky="w", padx=6, pady=2)
        actions = [
            ("Start",   lambda: self._rec("start")),
            ("Daemon",  lambda: self._rec("start", "--daemon")),
            ("Stop",    lambda: self._rec("stop")),
            ("Pause",   lambda: self._rec("pause")),
            ("Resume",  lambda: self._rec("resume")),
        ]
        for i, (label, cmd) in enumerate(actions):
            _btn(af, label, cmd, col=i)

        # Export row
        ef = tk.Frame(rec, bg=BG)
        ef.grid(row=2, column=0, sticky="w", padx=6, pady=(2, 6))
        _label(ef, "Date:", col=0)
        self._exp_date = _entry(ef, width=12)
        self._exp_date.insert(0, _date.today().isoformat())
        self._exp_date.grid(row=0, column=1, padx=4)
        self._inc_urls = tk.BooleanVar()
        _check(ef, "URLs", self._inc_urls, col=2)
        _btn(ef, "Export →", self._do_export, col=3, padx=(6, 0))

        # ── Dump → Note panel ─────────────────────────────────────────────────
        dump = _frame(self, " Dump → Note ")
        dump.grid(row=1, column=0, sticky="ew", **P)

        # File row
        ff = tk.Frame(dump, bg=BG)
        ff.grid(row=0, column=0, sticky="ew", padx=6, pady=(6, 2))
        _label(ff, "File:", col=0)
        self._file_var = tk.StringVar()
        tk.Entry(
            ff, textvariable=self._file_var, width=30,
            bg=BTN_BG, fg=FG, insertbackground=FG, relief="flat",
            highlightthickness=1, highlightbackground=BORDER,
        ).grid(row=0, column=1, padx=4)
        _btn(ff, "…", self._browse, col=2)

        # Tool / Date row
        td = tk.Frame(dump, bg=BG)
        td.grid(row=1, column=0, sticky="w", padx=6, pady=2)
        _label(td, "Tool:", col=0)
        self._tool_var = tk.StringVar()
        te = _entry(td, width=14, textvariable=self._tool_var)
        te.grid(row=0, column=1, padx=4)
        _label(td, "Date:", col=2, padx=(10, 4))
        self._d2n_date = _entry(td, width=12)
        self._d2n_date.insert(0, _date.today().isoformat())
        self._d2n_date.grid(row=0, column=3, padx=4)

        # Flags row
        flf = tk.Frame(dump, bg=BG)
        flf.grid(row=2, column=0, sticky="w", padx=6, pady=2)
        self._prev_var     = tk.BooleanVar()
        self._app_var      = tk.BooleanVar()
        self._noredact_var = tk.BooleanVar()
        self._hist_var     = tk.BooleanVar()
        _check(flf, "Preview",   self._prev_var,     col=0)
        _check(flf, "Append",    self._app_var,      col=1)
        _check(flf, "No-Redact", self._noredact_var, col=2)
        _check(flf, "History",   self._hist_var,     col=3)

        # History-lines + Run row
        br = tk.Frame(dump, bg=BG)
        br.grid(row=3, column=0, sticky="w", padx=6, pady=(2, 6))
        _label(br, "Hist lines:", col=0, padx=0)
        self._hist_lines = _entry(br, width=6)
        self._hist_lines.insert(0, "500")
        self._hist_lines.grid(row=0, column=1, padx=4)
        _btn(br, "Run dump2note", self._do_dump2note, col=2, padx=(8, 0))

        # ── Output console ────────────────────────────────────────────────────
        hdr = tk.Frame(self, bg=BG)
        hdr.grid(row=2, column=0, sticky="ew", padx=8, pady=(2, 0))
        _label(hdr, "Output", col=0, fg=MUTED, padx=0)
        _btn(hdr, "Clear", self._clear_log, col=1)

        self._log = scrolledtext.ScrolledText(
            self, height=8,
            bg=BG2, fg=FG, insertbackground=FG,
            relief="flat", highlightthickness=1, highlightbackground=BORDER,
            font=("TkFixedFont", 9), state="disabled",
        )
        self._log.grid(row=3, column=0, sticky="ew", padx=8, pady=(0, 8))
        self.columnconfigure(0, weight=1)

    # ── Logging ───────────────────────────────────────────────────────────────

    def _clear_log(self) -> None:
        self._log.configure(state="normal")
        self._log.delete("1.0", "end")
        self._log.configure(state="disabled")

    def _append(self, text: str) -> None:
        self._log.configure(state="normal")
        self._log.insert("end", text)
        self._log.see("end")
        self._log.configure(state="disabled")

    # ── Session recorder ──────────────────────────────────────────────────────

    def _rec(self, *args: str) -> None:
        if not RECORDER:
            self._append("[ERROR] session-recorder binary not found.\n"
                         "        Build it: cargo build --release "
                         "--manifest-path session-recorder/Cargo.toml\n")
            return
        cmd = [RECORDER, *args]
        threading.Thread(target=self._run_cmd, args=(cmd,), daemon=True).start()

    def _refresh_status(self) -> None:
        if not RECORDER:
            self._dot.config(fg=ERR)
            self._status_lbl.config(text="binary not found")
            return
        threading.Thread(target=self._fetch_status, daemon=True).start()

    def _fetch_status(self) -> None:
        try:
            r = subprocess.run(
                [RECORDER, "status"],
                capture_output=True, text=True, timeout=5,
            )
            out = (r.stdout + r.stderr).strip()
        except Exception as exc:
            out = str(exc)
        self.after(0, self._update_status, out)

    def _update_status(self, text: str) -> None:
        lo = text.lower()
        if "running" in lo or "recording" in lo:
            color, label = SUCCESS, "Running"
        elif "paused" in lo:
            color, label = WARN, "Paused"
        elif "stopped" in lo or "not running" in lo or "no session" in lo:
            color, label = MUTED, "Stopped"
        else:
            color = MUTED
            label = (text[:40] + "…") if len(text) > 40 else (text or "Unknown")
        self._dot.config(fg=color)
        self._status_lbl.config(text=label)

    def _do_export(self) -> None:
        args = ["export"]
        d = self._exp_date.get().strip()
        if d:
            args += ["--date", d]
        if self._inc_urls.get():
            args.append("--include-urls")
        self._rec(*args)

    def _run_cmd(self, cmd: list[str]) -> None:
        self.after(0, self._append, f"$ {' '.join(cmd)}\n")
        try:
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                text=True,
            )
            assert proc.stdout is not None, "subprocess stdout was unexpectedly None"
            for line in proc.stdout:
                self.after(0, self._append, line)
            proc.wait()
            self.after(0, self._append, f"[exit {proc.returncode}]\n\n")
        except Exception as exc:
            self.after(0, self._append, f"[ERROR] {exc}\n\n")
        finally:
            self.after(0, self._refresh_status)

    # ── dump2note ─────────────────────────────────────────────────────────────

    def _browse(self) -> None:
        path = filedialog.askopenfilename(title="Select dump file")
        if path:
            self._file_var.set(path)

    def _do_dump2note(self) -> None:
        if not _DUMP2NOTE.exists():
            self._append(f"[ERROR] dump2note.py not found at {_DUMP2NOTE}\n")
            return
        cmd: list[str] = [sys.executable, str(_DUMP2NOTE)]
        f = self._file_var.get().strip()
        if f:
            cmd.append(f)
        t = self._tool_var.get().strip()
        if t:
            cmd += ["--tool", t]
        d = self._d2n_date.get().strip()
        if d:
            cmd += ["--date", d]
        if self._prev_var.get():
            cmd.append("--preview")
        if self._app_var.get():
            cmd.append("--append")
        if self._noredact_var.get():
            cmd.append("--no-redact")
        if self._hist_var.get():
            hl = self._hist_lines.get().strip() or "500"
            cmd += ["--history", "--history-lines", hl]
        threading.Thread(target=self._run_cmd, args=(cmd,), daemon=True).start()


# ── Entry point ───────────────────────────────────────────────────────────────

def main() -> None:
    app = App()
    app.mainloop()


if __name__ == "__main__":
    main()
