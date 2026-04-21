#!/usr/bin/env python3
"""
session_recorder.py – Privacy-first background session recorder.

Records active window titles, clipboard changes, browser URLs, and terminal
commands across the entire desktop session.  Events are stored locally as
JSON-lines files and can be exported to structured notes via session2note.py.

Usage
-----
    python session_recorder.py start           # start recorder in foreground
    python session_recorder.py start --daemon  # fork into background (Unix)
    python session_recorder.py stop            # stop the running daemon
    python session_recorder.py status          # show status & available logs
    python session_recorder.py pause           # pause recording
    python session_recorder.py resume          # resume recording
    python session_recorder.py export          # export today's session to notes/
    python session_recorder.py export --date 2026-04-20 --preview
    python session_recorder.py config          # show current configuration

Options (start sub-command)
---------------------------
    --no-tray           Disable system tray icon
    --daemon            Fork into background (Unix only)
    --poll-interval N   Window poll interval in seconds (default: 5)
    --session-dir DIR   Directory to store session JSONL files
    --config FILE       Path to config JSON file

Requirements
------------
    Python 3.10+ (standard library only for core features)

    Optional packages for enhanced UX:
        pystray + Pillow  System tray icon (pip install pystray Pillow)
        pynput            Global hotkey  (pip install pynput)

Platform notes
--------------
    Linux   : requires xdotool for window titles; xclip or xsel for clipboard.
              Wayland sessions degrade gracefully (no window titles without
              xdotool Wayland support).
    macOS   : uses osascript (built-in) for window titles; pbpaste for clipboard.
    Windows : uses ctypes (built-in) for both window titles and clipboard.
"""

from __future__ import annotations

import argparse
import json
import os
import platform
import re
import shutil
import signal
import sqlite3
import subprocess
import sys
import tempfile
import threading
import time
from collections.abc import Callable
from dataclasses import asdict, dataclass, field
from datetime import date as _date
from datetime import datetime, timezone
from pathlib import Path

# ---------------------------------------------------------------------------
# Ensure same-directory imports work regardless of CWD
# ---------------------------------------------------------------------------
_SCRIPT_DIR = Path(__file__).resolve().parent
if str(_SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(_SCRIPT_DIR))

# ---------------------------------------------------------------------------
# Optional dependencies (graceful fallback when not installed)
# ---------------------------------------------------------------------------
try:
    import pystray as _pystray
    from PIL import Image as _PILImage, ImageDraw as _PILDraw
    _HAS_TRAY = True
except ImportError:
    _HAS_TRAY = False

try:
    from pynput import keyboard as _pynput_keyboard
    _HAS_PYNPUT = True
except ImportError:
    _HAS_PYNPUT = False

# ---------------------------------------------------------------------------
# Re-use redaction logic from dump2note when available
# ---------------------------------------------------------------------------
try:
    from dump2note import redact as _dump2note_redact
    _HAS_DUMP2NOTE = True
except ImportError:
    _HAS_DUMP2NOTE = False

    def _dump2note_redact(text: str) -> str:  # type: ignore[misc]
        return text

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
_PLATFORM = platform.system()   # 'Linux' | 'Darwin' | 'Windows'
_XDG_DATA = Path(
    os.environ.get('XDG_DATA_HOME', '~/.local/share')
).expanduser()
_SESSION_ROOT = _XDG_DATA / 'session-logger'
_DEFAULT_SESSION_DIR = _SESSION_ROOT / 'sessions'
_DEFAULT_CONFIG_PATH = Path(
    os.environ.get('XDG_CONFIG_HOME', '~/.config')
).expanduser() / 'session-logger' / 'config.json'
_DEFAULT_PID_FILE = _SESSION_ROOT / 'recorder.pid'
_DEFAULT_PAUSE_FILE = _SESSION_ROOT / 'recorder.paused'

_DEFAULT_POLL_INTERVAL = 5      # seconds between window-title polls
_DEFAULT_CLIP_INTERVAL = 2      # seconds between clipboard polls
_DEFAULT_MAX_CLIP_LEN = 2000    # max clipboard characters to store

# ---------------------------------------------------------------------------
# Default privacy exclude lists
# ---------------------------------------------------------------------------
_DEFAULT_EXCLUDE_APPS: list[str] = [
    '1password', 'keepass', 'keepassxc', 'bitwarden', 'lastpass',
    'dashlane', 'enpass', 'gnome-keyring', 'kwallet', 'pass',
]
_DEFAULT_EXCLUDE_WINDOW_PATTERNS: list[str] = [
    r'\bpassword\b', r'\bpasswd\b', r'\bpin\b', r'\bsecret\b',
    r'\bpayment\b', r'\bcredit.?card\b', r'\bsocial.?security\b',
    r'\bssn\b',
]

# ---------------------------------------------------------------------------
# EventRecord
# ---------------------------------------------------------------------------

@dataclass
class EventRecord:
    """A single captured desktop event."""

    ts: str             # ISO-8601 timestamp (UTC)
    type: str           # window | clipboard | browser_url | command | system
    source: str         # sensor name
    data: str           # event content
    app: str = ''       # lowercase app/process name
    extra: dict = field(default_factory=dict)

    def to_json(self) -> str:
        return json.dumps(asdict(self))

    @classmethod
    def from_json(cls, line: str) -> 'EventRecord':
        d = json.loads(line)
        return cls(**d)

    @staticmethod
    def now_ts() -> str:
        return datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')


# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

_DEFAULT_CONFIG: dict = {
    'poll_interval': _DEFAULT_POLL_INTERVAL,
    'clipboard_poll_interval': _DEFAULT_CLIP_INTERVAL,
    'max_clipboard_length': _DEFAULT_MAX_CLIP_LEN,
    'exclude_apps': _DEFAULT_EXCLUDE_APPS,
    'exclude_window_patterns': _DEFAULT_EXCLUDE_WINDOW_PATTERNS,
    'browser_history_on_export': True,
    'hotkey': 'ctrl+shift+F12',
    'tray_icon': True,
    'redact': True,
    'session_dir': str(_DEFAULT_SESSION_DIR),
}


class Config:
    """Loads, merges, and persists recorder configuration."""

    def __init__(self, path: Path | None = None) -> None:
        self._path = path or _DEFAULT_CONFIG_PATH
        self._data: dict = dict(_DEFAULT_CONFIG)
        self._load()

    def _load(self) -> None:
        if self._path.is_file():
            try:
                loaded = json.loads(self._path.read_text())
                self._data.update(loaded)
            except (json.JSONDecodeError, OSError):
                pass

    def get(self, key: str, default=None):
        return self._data.get(key, default)

    def set(self, key: str, value) -> None:
        self._data[key] = value

    def save(self) -> None:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._path.write_text(json.dumps(self._data, indent=2))

    def is_excluded_app(self, app_name: str) -> bool:
        name_lower = app_name.lower()
        for pattern in self.get('exclude_apps', []):
            if pattern.lower() in name_lower:
                return True
        return False

    def is_excluded_window(self, title: str) -> bool:
        for pattern in self.get('exclude_window_patterns', []):
            if re.search(pattern, title, re.IGNORECASE):
                return True
        return False

    @property
    def session_dir(self) -> Path:
        return Path(self.get('session_dir', str(_DEFAULT_SESSION_DIR))).expanduser()

    @property
    def poll_interval(self) -> int:
        return int(self.get('poll_interval', _DEFAULT_POLL_INTERVAL))

    @property
    def clip_interval(self) -> int:
        return int(self.get('clipboard_poll_interval', _DEFAULT_CLIP_INTERVAL))

    @property
    def max_clip_len(self) -> int:
        return int(self.get('max_clipboard_length', _DEFAULT_MAX_CLIP_LEN))


# ---------------------------------------------------------------------------
# Event store (JSONL per day)
# ---------------------------------------------------------------------------

class EventStore:
    """Appends EventRecord objects to a JSONL file per day."""

    def __init__(self, session_dir: Path) -> None:
        self._dir = session_dir
        self._lock = threading.Lock()

    def _path_for(self, date_str: str) -> Path:
        year = date_str[:4]
        p = self._dir / year / f'{date_str}.jsonl'
        p.parent.mkdir(parents=True, exist_ok=True)
        return p

    def write(self, event: EventRecord) -> None:
        date_str = event.ts[:10]
        path = self._path_for(date_str)
        with self._lock:
            with path.open('a') as fh:
                fh.write(event.to_json() + '\n')

    def read(self, date_str: str) -> list[EventRecord]:
        path = self._path_for(date_str)
        if not path.is_file():
            return []
        events: list[EventRecord] = []
        for line in path.read_text().splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                events.append(EventRecord.from_json(line))
            except (json.JSONDecodeError, TypeError):
                continue
        return events

    def available_dates(self) -> list[str]:
        return sorted(p.stem for p in self._dir.rglob('*.jsonl'))


# ---------------------------------------------------------------------------
# Platform helpers – active window
# ---------------------------------------------------------------------------

def _run(cmd: list[str], timeout: float = 3.0) -> str:
    """Run a subprocess and return stdout, or '' on any error."""
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout,
        )
        return result.stdout.strip()
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        return ''


def _get_active_window_linux() -> tuple[str, str]:
    """Return (window_title, app_name) on Linux via xdotool + xprop."""
    win_id = _run(['xdotool', 'getwindowfocus'])
    if not win_id:
        return '', ''
    title = _run(['xdotool', 'getwindowname', win_id])
    raw_class = _run(['xprop', '-id', win_id, 'WM_CLASS'])
    app = ''
    if 'WM_CLASS' in raw_class:
        parts = re.findall(r'"([^"]+)"', raw_class)
        app = parts[-1].lower() if parts else ''
    return title, app


def _get_active_window_macos() -> tuple[str, str]:
    """Return (window_title, app_name) on macOS via osascript."""
    script = (
        'tell application "System Events" to get '
        '{name of first process whose frontmost is true, '
        'name of front window of first application process whose frontmost is true}'
    )
    raw = _run(['osascript', '-e', script])
    if not raw:
        app_script = (
            'tell application "System Events" to '
            'get name of first process whose frontmost is true'
        )
        app = _run(['osascript', '-e', app_script])
        return '', app.lower()
    parts = [p.strip() for p in raw.split(',', 1)]
    app = parts[0].lower() if parts else ''
    title = parts[1] if len(parts) > 1 else ''
    return title, app


def _get_active_window_windows() -> tuple[str, str]:
    """Return (window_title, app_name) on Windows via ctypes."""
    try:
        import ctypes
        import ctypes.wintypes as wintypes
        user32 = ctypes.windll.user32   # type: ignore[attr-defined]
        hwnd = user32.GetForegroundWindow()
        length = user32.GetWindowTextLengthW(hwnd)
        buf = ctypes.create_unicode_buffer(length + 1)
        user32.GetWindowTextW(hwnd, buf, length + 1)
        title = buf.value
        pid = wintypes.DWORD()
        user32.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
        kernel32 = ctypes.windll.kernel32   # type: ignore[attr-defined]
        handle = kernel32.OpenProcess(0x0400 | 0x0010, False, pid.value)
        app = ''
        if handle:
            exe_buf = ctypes.create_unicode_buffer(512)
            psapi = ctypes.windll.psapi   # type: ignore[attr-defined]
            psapi.GetModuleFileNameExW(handle, None, exe_buf, 512)
            kernel32.CloseHandle(handle)
            app = Path(exe_buf.value).stem.lower() if exe_buf.value else ''
        return title, app
    except Exception:
        return '', ''


def get_active_window() -> tuple[str, str]:
    """Return (window_title, app_name) for the current platform."""
    if _PLATFORM == 'Linux':
        return _get_active_window_linux()
    if _PLATFORM == 'Darwin':
        return _get_active_window_macos()
    if _PLATFORM == 'Windows':
        return _get_active_window_windows()
    return '', ''


# ---------------------------------------------------------------------------
# Platform helpers – clipboard
# ---------------------------------------------------------------------------

def _get_clipboard_linux() -> str:
    text = _run(['xclip', '-selection', 'clipboard', '-o'])
    if not text:
        text = _run(['xsel', '--clipboard', '--output'])
    return text


def _get_clipboard_macos() -> str:
    return _run(['pbpaste'])


def _get_clipboard_windows() -> str:
    try:
        import ctypes
        user32 = ctypes.windll.user32   # type: ignore[attr-defined]
        if not user32.OpenClipboard(0):
            return ''
        CF_UNICODETEXT = 13
        h_data = user32.GetClipboardData(CF_UNICODETEXT)
        if not h_data:
            user32.CloseClipboard()
            return ''
        kernel32 = ctypes.windll.kernel32   # type: ignore[attr-defined]
        ptr = kernel32.GlobalLock(h_data)
        text = ctypes.wstring_at(ptr) if ptr else ''
        kernel32.GlobalUnlock(h_data)
        user32.CloseClipboard()
        return text
    except Exception:
        return ''


def get_clipboard() -> str:
    """Return current clipboard text for the current platform."""
    if _PLATFORM == 'Linux':
        return _get_clipboard_linux()
    if _PLATFORM == 'Darwin':
        return _get_clipboard_macos()
    if _PLATFORM == 'Windows':
        return _get_clipboard_windows()
    return ''


# ---------------------------------------------------------------------------
# Browser history importer
# ---------------------------------------------------------------------------

# Each entry lists candidate paths for the browser's history DB.
# Environment variables and ~ are expanded at runtime.
_CHROMIUM_PROFILES: dict[str, list[str]] = {
    'chrome': [
        '~/.config/google-chrome/Default/History',
        '~/Library/Application Support/Google/Chrome/Default/History',
        '%LOCALAPPDATA%/Google/Chrome/User Data/Default/History',
    ],
    'chromium': [
        '~/.config/chromium/Default/History',
        '~/Library/Application Support/Chromium/Default/History',
    ],
    'edge': [
        '~/.config/microsoft-edge/Default/History',
        '~/Library/Application Support/Microsoft Edge/Default/History',
        '%LOCALAPPDATA%/Microsoft/Edge/User Data/Default/History',
    ],
    'brave': [
        '~/.config/BraveSoftware/Brave-Browser/Default/History',
        '~/Library/Application Support/BraveSoftware/Brave-Browser/Default/History',
    ],
}


def _expand_path(raw: str) -> Path:
    return Path(os.path.expandvars(os.path.expanduser(raw)))


def _find_firefox_histories() -> list[Path]:
    bases = [
        '~/.mozilla/firefox',
        '~/Library/Application Support/Firefox/Profiles',
        '%APPDATA%/Mozilla/Firefox/Profiles',
    ]
    paths: list[Path] = []
    for raw in bases:
        base = _expand_path(raw)
        if base.is_dir():
            paths.extend(base.glob('*.default*/places.sqlite'))
            paths.extend(base.glob('*/places.sqlite'))
    return paths


def _read_chromium_history(db_path: Path, since_ts: int, limit: int = 200) -> list[str]:
    """Read recent URLs from a Chromium-family History SQLite DB."""
    urls: list[str] = []
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_db = Path(tmpdir) / 'History'
        try:
            shutil.copy2(db_path, tmp_db)
        except OSError:
            return urls
        try:
            # Chrome timestamps: microseconds since 1601-01-01
            chrome_since = (since_ts + 11_644_473_600) * 1_000_000
            con = sqlite3.connect(str(tmp_db))
            rows = con.execute(
                'SELECT url FROM urls '
                'WHERE last_visit_time > ? '
                'ORDER BY last_visit_time DESC LIMIT ?',
                (chrome_since, limit),
            ).fetchall()
            con.close()
            urls = [r[0] for r in rows]
        except sqlite3.Error:
            pass
    return urls


def _read_firefox_history(db_path: Path, since_ts: int, limit: int = 200) -> list[str]:
    """Read recent URLs from a Firefox places.sqlite DB."""
    urls: list[str] = []
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_db = Path(tmpdir) / 'places.sqlite'
        try:
            shutil.copy2(db_path, tmp_db)
        except OSError:
            return urls
        try:
            # Firefox timestamps: microseconds since Unix epoch
            firefox_since = since_ts * 1_000_000
            con = sqlite3.connect(str(tmp_db))
            rows = con.execute(
                'SELECT DISTINCT p.url '
                'FROM moz_places p '
                'JOIN moz_historyvisits v ON p.id = v.place_id '
                'WHERE v.visit_date > ? '
                'ORDER BY v.visit_date DESC LIMIT ?',
                (firefox_since, limit),
            ).fetchall()
            con.close()
            urls = [r[0] for r in rows]
        except sqlite3.Error:
            pass
    return urls


# Redact sensitive query parameters from URLs before storing
_URL_SENSITIVE_RE = re.compile(
    r'([?&](?:password|passwd|token|secret|api[_-]?key|access[_-]?key|auth)[^&#]*)',
    re.IGNORECASE,
)


def _redact_url(url: str) -> str:
    return _URL_SENSITIVE_RE.sub('[REDACTED_PARAM]', url)


def import_browser_history(
    since_ts: int | None = None,
    limit_per_browser: int = 200,
    do_redact: bool = True,
) -> list[EventRecord]:
    """Import recent browser history as EventRecord objects."""
    if since_ts is None:
        since_ts = int(time.time()) - 86400   # last 24 hours
    ts_str = EventRecord.now_ts()
    events: list[EventRecord] = []

    for browser, raw_paths in _CHROMIUM_PROFILES.items():
        for raw in raw_paths:
            db_path = _expand_path(raw)
            if db_path.is_file():
                for url in _read_chromium_history(db_path, since_ts, limit_per_browser):
                    if do_redact:
                        url = _redact_url(url)
                    events.append(EventRecord(
                        ts=ts_str, type='browser_url',
                        source=browser, data=url, app=browser,
                    ))
                break   # only use first found profile per browser

    for db_path in _find_firefox_histories():
        for url in _read_firefox_history(db_path, since_ts, limit_per_browser):
            if do_redact:
                url = _redact_url(url)
            events.append(EventRecord(
                ts=ts_str, type='browser_url',
                source='firefox', data=url, app='firefox',
            ))

    return events


# ---------------------------------------------------------------------------
# Optional: system tray icon
# ---------------------------------------------------------------------------

class _TrayIcon:
    """Wraps pystray to show a 'recording' indicator in the system tray."""

    def __init__(
        self,
        on_stop: Callable[[], None],
        on_pause: Callable[[], None],
        on_resume: Callable[[], None],
    ) -> None:
        self._on_stop = on_stop
        self._on_pause = on_pause
        self._on_resume = on_resume
        self._paused = False
        self._icon = None

    def _make_image(self, recording: bool):
        size = 64
        img = _PILImage.new('RGB', (size, size), (30, 30, 30))
        draw = _PILDraw.Draw(img)
        colour = (0, 200, 0) if recording else (200, 100, 0)
        draw.ellipse([16, 16, 48, 48], fill=colour)
        return img

    def start(self) -> None:
        if not _HAS_TRAY:
            return
        try:
            icon_obj = [None]   # mutable container so nested funcs can write it

            def _toggle_pause(icon, item):  # noqa: ARG001
                self._paused = not self._paused
                if self._paused:
                    self._on_pause()
                    icon.icon = self._make_image(False)
                    icon.title = 'Session Recorder (paused)'
                else:
                    self._on_resume()
                    icon.icon = self._make_image(True)
                    icon.title = 'Session Recorder (recording)'
                icon.update_menu()

            def _stop(icon, item):  # noqa: ARG001
                self._on_stop()
                icon.stop()

            menu = _pystray.Menu(
                _pystray.MenuItem('Session Recorder', None, enabled=False),
                _pystray.Menu.SEPARATOR,
                _pystray.MenuItem(
                    lambda _: 'Resume recording' if self._paused else 'Pause recording',
                    _toggle_pause,
                ),
                _pystray.MenuItem('Stop recorder', _stop),
            )
            self._icon = _pystray.Icon(
                'session-recorder',
                self._make_image(True),
                'Session Recorder (recording)',
                menu,
            )
            icon_obj[0] = self._icon
            t = threading.Thread(target=self._icon.run, daemon=True)
            t.start()
        except Exception:
            pass    # graceful fallback if display not available

    def stop(self) -> None:
        if self._icon:
            try:
                self._icon.stop()
            except Exception:
                pass


# ---------------------------------------------------------------------------
# Optional: global hotkey listener
# ---------------------------------------------------------------------------

class _HotkeyListener:
    """Listens for a global hotkey using pynput."""

    def __init__(self, hotkey_str: str, callback: Callable[[], None]) -> None:
        self._hotkey = hotkey_str
        self._callback = callback
        self._listener = None

    def start(self) -> None:
        if not _HAS_PYNPUT:
            return
        try:
            self._listener = _pynput_keyboard.GlobalHotKeys(
                {self._hotkey: self._callback}
            )
            self._listener.daemon = True
            self._listener.start()
        except Exception:
            pass

    def stop(self) -> None:
        if self._listener:
            try:
                self._listener.stop()
            except Exception:
                pass


# ---------------------------------------------------------------------------
# Recorder daemon
# ---------------------------------------------------------------------------

class RecorderDaemon:
    """Main background recording loop."""

    def __init__(
        self,
        config: Config,
        session_dir: Path | None = None,
        enable_tray: bool = True,
    ) -> None:
        self._config = config
        self._store = EventStore(session_dir or config.session_dir)
        self._running = False
        self._paused = False
        self._last_window: str = ''
        self._last_clip: str = ''
        self._tray: _TrayIcon | None = None
        self._hotkey: _HotkeyListener | None = None
        self._enable_tray = enable_tray

    def _is_paused(self) -> bool:
        return _DEFAULT_PAUSE_FILE.is_file() or self._paused

    def pause(self) -> None:
        self._paused = True
        _DEFAULT_PAUSE_FILE.parent.mkdir(parents=True, exist_ok=True)
        _DEFAULT_PAUSE_FILE.touch()

    def resume(self) -> None:
        self._paused = False
        _DEFAULT_PAUSE_FILE.unlink(missing_ok=True)

    def stop(self) -> None:
        self._running = False
        self.resume()
        if self._tray:
            self._tray.stop()
        if self._hotkey:
            self._hotkey.stop()

    def _collect_window(self) -> None:
        title, app = get_active_window()
        if not title and not app:
            return
        if self._config.is_excluded_app(app):
            return
        if title and self._config.is_excluded_window(title):
            return
        label = title or app
        if label == self._last_window:
            return
        self._last_window = label
        self._store.write(EventRecord(
            ts=EventRecord.now_ts(),
            type='window',
            source='window_tracker',
            data=label,
            app=app,
        ))

    def _collect_clipboard(self) -> None:
        text = get_clipboard()
        if not text or text == self._last_clip:
            return
        if len(text) > self._config.max_clip_len:
            text = text[:self._config.max_clip_len] + ' [TRUNCATED]'
        if self._config.get('redact', True):
            text = _dump2note_redact(text)
        self._last_clip = text
        self._store.write(EventRecord(
            ts=EventRecord.now_ts(),
            type='clipboard',
            source='clipboard_tracker',
            data=text,
        ))

    def start(self) -> None:
        """Run the main daemon loop (blocks until stopped)."""
        self._running = True
        _write_pid()

        self._store.write(EventRecord(
            ts=EventRecord.now_ts(), type='system',
            source='recorder', data='Recording started',
        ))
        print(f'[session_recorder] Recording started (PID {os.getpid()})')
        print('[session_recorder] Press Ctrl-C or run "stop" to end the session.')

        # Optional tray icon
        if self._enable_tray and self._config.get('tray_icon', True):
            self._tray = _TrayIcon(
                on_stop=self.stop,
                on_pause=self.pause,
                on_resume=self.resume,
            )
            self._tray.start()

        # Optional hotkey
        hotkey_str = self._config.get('hotkey', '')
        if hotkey_str:
            self._hotkey = _HotkeyListener(hotkey_str, self.stop)
            self._hotkey.start()

        signal.signal(signal.SIGTERM, lambda *_: self.stop())
        signal.signal(signal.SIGINT, lambda *_: self.stop())

        poll = self._config.poll_interval
        clip_poll = self._config.clip_interval
        last_clip_time = 0.0

        while self._running:
            if not self._is_paused():
                try:
                    self._collect_window()
                except Exception:
                    pass
                if time.time() - last_clip_time >= clip_poll:
                    try:
                        self._collect_clipboard()
                    except Exception:
                        pass
                    last_clip_time = time.time()
            time.sleep(poll)

        self._store.write(EventRecord(
            ts=EventRecord.now_ts(), type='system',
            source='recorder', data='Recording stopped',
        ))
        _remove_pid()
        print('[session_recorder] Recording stopped.')


# ---------------------------------------------------------------------------
# Daemon process management
# ---------------------------------------------------------------------------

def _write_pid() -> None:
    _DEFAULT_PID_FILE.parent.mkdir(parents=True, exist_ok=True)
    _DEFAULT_PID_FILE.write_text(str(os.getpid()))


def _remove_pid() -> None:
    _DEFAULT_PID_FILE.unlink(missing_ok=True)


def _read_pid() -> int | None:
    if not _DEFAULT_PID_FILE.is_file():
        return None
    try:
        return int(_DEFAULT_PID_FILE.read_text().strip())
    except (ValueError, OSError):
        return None


def _is_process_running(pid: int) -> bool:
    try:
        os.kill(pid, 0)
        return True
    except (ProcessLookupError, PermissionError, OSError):
        return False


# ---------------------------------------------------------------------------
# Command handlers
# ---------------------------------------------------------------------------

def cmd_start(args: argparse.Namespace, config: Config) -> int:
    pid = _read_pid()
    if pid and _is_process_running(pid):
        print(f'ERROR: Recorder is already running (PID {pid}).', file=sys.stderr)
        return 1

    if getattr(args, 'daemon', False):
        if _PLATFORM == 'Windows':
            print(
                'ERROR: --daemon is not supported on Windows. '
                'Run without --daemon or use Task Scheduler.',
                file=sys.stderr,
            )
            return 1
        child_pid = os.fork()
        if child_pid > 0:
            print(f'[session_recorder] Started in background (PID {child_pid})')
            return 0
        # Child: detach from terminal
        os.setsid()
        sys.stdin = open(os.devnull, 'r')   # noqa: SIM115
        sys.stdout = open(os.devnull, 'w')  # noqa: SIM115
        sys.stderr = open(os.devnull, 'w')  # noqa: SIM115

    session_dir = (
        Path(args.session_dir).expanduser()
        if getattr(args, 'session_dir', None)
        else config.session_dir
    )
    daemon = RecorderDaemon(config, session_dir, enable_tray=not args.no_tray)
    daemon.start()
    return 0


def cmd_stop(args: argparse.Namespace, config: Config) -> int:  # noqa: ARG001
    pid = _read_pid()
    if not pid:
        print('No recorder is running (no PID file found).', file=sys.stderr)
        return 1
    if not _is_process_running(pid):
        print(f'Recorder process {pid} is not running. Removing stale PID file.')
        _remove_pid()
        return 0
    try:
        os.kill(pid, signal.SIGTERM)
        print(f'Sent SIGTERM to recorder (PID {pid}).')
        return 0
    except PermissionError:
        print(f'ERROR: Permission denied to stop PID {pid}.', file=sys.stderr)
        return 1


def cmd_status(args: argparse.Namespace, config: Config) -> int:  # noqa: ARG001
    pid = _read_pid()
    if not pid or not _is_process_running(pid):
        print('Recorder: NOT running')
    else:
        state = 'PAUSED' if _DEFAULT_PAUSE_FILE.is_file() else 'RUNNING'
        print(f'Recorder: {state} (PID {pid})')

    store = EventStore(config.session_dir)
    dates = store.available_dates()
    if dates:
        shown = dates[-5:]
        suffix = '...' if len(dates) > 5 else ''
        print(f'Session logs available for: {", ".join(shown)}{suffix}')
    else:
        print('No session logs yet.')
    return 0


def cmd_pause(args: argparse.Namespace, config: Config) -> int:  # noqa: ARG001
    pid = _read_pid()
    if not pid or not _is_process_running(pid):
        print('ERROR: Recorder is not running.', file=sys.stderr)
        return 1
    _DEFAULT_PAUSE_FILE.parent.mkdir(parents=True, exist_ok=True)
    _DEFAULT_PAUSE_FILE.touch()
    print('Recording paused. Run "resume" to continue.')
    return 0


def cmd_resume(args: argparse.Namespace, config: Config) -> int:  # noqa: ARG001
    _DEFAULT_PAUSE_FILE.unlink(missing_ok=True)
    print('Recording resumed.')
    return 0


def cmd_export(args: argparse.Namespace, config: Config) -> int:
    date_str = getattr(args, 'date', None) or _date.today().isoformat()
    # Verify events exist before delegating
    session_dir = (
        Path(args.session_dir).expanduser()
        if getattr(args, 'session_dir', None)
        else config.session_dir
    )
    store = EventStore(session_dir)
    if not store.read(date_str):
        print(f'No session events found for {date_str}.', file=sys.stderr)
        return 1

    script = _SCRIPT_DIR / 'session2note.py'
    if not script.is_file():
        print(
            f'ERROR: session2note.py not found at {script}.',
            file=sys.stderr,
        )
        return 1

    cmd: list[str] = [sys.executable, str(script), '--date', date_str,
                      '--session-dir', str(session_dir)]
    if getattr(args, 'preview', False):
        cmd.append('--preview')
    if getattr(args, 'tool', None):
        cmd += ['--tool', args.tool]
    if getattr(args, 'output_dir', None):
        cmd += ['--output-dir', args.output_dir]
    if getattr(args, 'no_redact', False):
        cmd.append('--no-redact')
    if config.get('browser_history_on_export', True):
        cmd.append('--browser-history')

    return subprocess.call(cmd)


def cmd_config(args: argparse.Namespace, config: Config) -> int:  # noqa: ARG001
    print(f'Config file: {config._path}')
    print(json.dumps(config._data, indent=2))
    return 0


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def parse_args(argv: list[str]) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog='session_recorder.py',
        description='Privacy-first background session recorder for the whole desktop.',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            'Examples:\n'
            '  python session_recorder.py start             # start (foreground)\n'
            '  python session_recorder.py start --daemon    # start in background\n'
            '  python session_recorder.py start --no-tray   # no tray icon\n'
            '  python session_recorder.py stop\n'
            '  python session_recorder.py status\n'
            '  python session_recorder.py pause\n'
            '  python session_recorder.py resume\n'
            '  python session_recorder.py export\n'
            '  python session_recorder.py export --date 2026-04-20 --preview\n'
            '  python session_recorder.py config\n'
        ),
    )
    sub = p.add_subparsers(dest='command', required=True)

    # start
    sp = sub.add_parser('start', help='Start the background recorder')
    sp.add_argument('--no-tray', action='store_true',
                    help='Disable system tray icon')
    sp.add_argument('--daemon', action='store_true',
                    help='Fork into background (Unix only)')
    sp.add_argument('--poll-interval', type=int,
                    help='Window poll interval in seconds')
    sp.add_argument('--session-dir',
                    help='Directory to store session JSONL files')
    sp.add_argument('--config', dest='config_file',
                    help='Path to config JSON file')

    # stop
    sub.add_parser('stop', help='Stop the running recorder')

    # status
    sub.add_parser('status', help='Show status and available session logs')

    # pause
    sub.add_parser('pause', help='Pause recording')

    # resume
    sub.add_parser('resume', help='Resume paused recording')

    # export
    ep = sub.add_parser('export', help='Export a session log to a structured note')
    ep.add_argument('--date', help='Date to export (YYYY-MM-DD, default: today)')
    ep.add_argument('--tool', help='Force tool name')
    ep.add_argument('--preview', action='store_true',
                    help='Print note without writing to disk')
    ep.add_argument('--no-redact', dest='no_redact', action='store_true',
                    help='Disable automatic redaction')
    ep.add_argument('--output-dir', dest='output_dir',
                    help='Notes output directory (default: notes/)')
    ep.add_argument('--session-dir',
                    help='Directory containing session JSONL files')

    # config
    sub.add_parser('config', help='Show current configuration')

    return p.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv if argv is not None else sys.argv[1:])

    config_path = getattr(args, 'config_file', None)
    config = Config(Path(config_path).expanduser() if config_path else None)

    if getattr(args, 'poll_interval', None):
        config.set('poll_interval', args.poll_interval)
    if getattr(args, 'session_dir', None):
        config.set('session_dir', args.session_dir)

    dispatch = {
        'start': cmd_start,
        'stop': cmd_stop,
        'status': cmd_status,
        'pause': cmd_pause,
        'resume': cmd_resume,
        'export': cmd_export,
        'config': cmd_config,
    }
    return dispatch[args.command](args, config)


if __name__ == '__main__':
    sys.exit(main())
