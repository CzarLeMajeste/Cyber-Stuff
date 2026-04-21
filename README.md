# Session Logger

This repo contains  my session logger.

## Notes structure

Use the `notes/` folder to organize notes by **tool** and **date**:

```text
notes/
  <tool-name>/
    YYYY/
      YYYY-MM-DD.md
```

Example:

```text
notes/
  nmap/
    2026/
      2026-04-17.md
```

You can copy the template file at `notes/_template_tool/YYYY/YYYY-MM-DD.md` when creating new notes.

## Converting a data dump to a comprehensive note

Use `dump2note.py` to automatically convert a raw data dump (terminal logs,
command history, pasted output, etc.) into a structured Markdown note that
follows the repository conventions.

### Requirements

Python 3.10 or newer (standard library only – no additional packages needed).

### Quick start

```bash
# Interactive – paste your dump, confirm tool/date, note is written to notes/
python dump2note.py

# From a saved file
python dump2note.py session.log

# Preview the generated note without writing to disk
python dump2note.py session.log --preview

# Force tool name and date (skips auto-detection prompts)
python dump2note.py session.log --tool nmap --date 2026-04-17

# Pipe output directly from another command
nmap -sV -sC 10.10.10.5 | python dump2note.py --tool nmap

# Auto-ingest recent terminal session history
python dump2note.py --history --history-lines 300

# Append to an existing note instead of overwriting
python dump2note.py more-findings.log --tool nmap --date 2026-04-17 --append

# Disable automatic redaction of sensitive values
python dump2note.py session.log --no-redact
```

### What it does

| Step | Description |
|------|-------------|
| **Ingest** | Reads from a file path or stdin |
| **Detect** | Auto-detects tool name and date from content; prompts you to confirm or override |
| **Normalize** | Deduplicates repeated lines and collapses blank-line runs |
| **Classify** | Sorts lines into *Commands / Steps*, *Findings*, *Follow-ups*, and *Raw Notes* |
| **Redact** | Removes passwords, API tokens, JWTs, and AWS keys from the output (disable with `--no-redact`) |
| **Format** | Produces Obsidian-friendly Markdown with YAML frontmatter and task-style follow-ups |
| **Write** | Creates `notes/<tool>/<YYYY>/<YYYY-MM-DD>.md` (merges or appends if the file already exists) |

### Options

```
usage: dump2note.py [DUMP_FILE] [OPTIONS]

positional arguments:
  DUMP_FILE             Path to raw dump file (default: stdin)

options:
  --tool TOOL           Force tool name (skips auto-detection)
  --date DATE           Force date as YYYY-MM-DD (default: today)
  --preview             Print the generated note without writing to disk
  --append              Append to an existing note instead of overwriting
  --no-redact           Disable automatic redaction of sensitive values
  --history             Auto-read the current shell history and convert it
  --history-lines N     Number of recent history lines to ingest (default: 500)
  --output-dir DIR      Root directory for notes (default: notes/)
  -h, --help            Show this help message
```

### Sample dumps

The `examples/` directory contains three sample dumps you can use to try the tool:

| File | Description |
|------|-------------|
| `examples/nmap-clean.txt` | Clean nmap scan output |
| `examples/noisy-session.txt` | Noisy terminal session with chat and false starts |
| `examples/multi-tool.txt` | Multi-tool session (nmap + gobuster + sqlmap + metasploit) |

```bash
python dump2note.py examples/nmap-clean.txt --preview
python dump2note.py examples/noisy-session.txt --preview
python dump2note.py examples/multi-tool.txt --preview
```

## Background session recorder

Use `session_recorder.py` to capture your **entire desktop session** in the
background – active window titles, clipboard changes, browser URLs, and
terminal commands – and later convert the recording into a structured note.

### Requirements

- Python 3.10+ (standard library only for core features)
- **Linux**: `xdotool` for window titles; `xclip` or `xsel` for clipboard
- **macOS**: `osascript` (built-in); `pbpaste` (built-in)
- **Windows**: `ctypes` (built-in)

Optional packages for enhanced UX:

| Package | Feature | Install |
|---------|---------|---------|
| `pystray` + `Pillow` | System tray icon with pause/stop controls | `pip install pystray Pillow` |
| `pynput` | Global hotkey kill switch | `pip install pynput` |

### Quick start

```bash
# Start recording in the foreground (Ctrl-C to stop)
python session_recorder.py start

# Start in the background (Unix only)
python session_recorder.py start --daemon

# Check status
python session_recorder.py status

# Pause / resume without stopping
python session_recorder.py pause
python session_recorder.py resume

# Stop the daemon
python session_recorder.py stop

# Export today's session to notes/
python session_recorder.py export

# Preview the note without writing it
python session_recorder.py export --preview

# Export a specific date
python session_recorder.py export --date 2026-04-20
```

### What it records

| Sensor | Data captured | Platform |
|--------|--------------|----------|
| **Window tracker** | Active window title and app name (polls every 5 s by default) | Linux (X11), macOS, Windows |
| **Clipboard tracker** | Text copied to the clipboard (polls every 2 s) | Linux, macOS, Windows |
| **Browser history** | Recent URLs from Chrome, Chromium, Edge, Brave, Firefox (imported on export) | All |

### Privacy controls

All captured data is stored **locally only** in
`~/.local/share/session-logger/sessions/<YYYY>/<YYYY-MM-DD>.jsonl`.

| Control | How it works |
|---------|-------------|
| **Exclude apps** | Apps listed in `exclude_apps` (e.g. password managers) are never captured |
| **Exclude window patterns** | Titles matching `exclude_window_patterns` (e.g. containing "password") are skipped |
| **Redaction** | Passwords, tokens, JWTs, and AWS keys are redacted before storage (disable with `--no-redact`) |
| **Clipboard length cap** | Clipboard content is truncated at 2 000 characters |
| **Pause / resume** | Recording can be paused at any time via CLI, tray menu, or hotkey |
| **Hotkey kill switch** | Default hotkey `Ctrl+Shift+F12` stops recording immediately (requires `pynput`) |

### Options (start sub-command)

```
  --no-tray           Disable system tray icon
  --daemon            Fork into background (Unix only)
  --poll-interval N   Window poll interval in seconds (default: 5)
  --session-dir DIR   Directory to store session JSONL files
  --config FILE       Path to config JSON file
```

### Options (export sub-command)

```
  --date DATE         Date to export as YYYY-MM-DD (default: today)
  --tool TOOL         Force tool name (skips auto-detection)
  --preview           Print note without writing to disk
  --no-redact         Disable automatic redaction
  --output-dir DIR    Notes root directory (default: notes/)
  --session-dir DIR   Directory containing session JSONL files
```

### Configuration

The configuration file lives at `~/.config/session-logger/config.json` and
is created automatically on first use.  Show it with:

```bash
python session_recorder.py config
```

Key settings:

| Key | Default | Description |
|-----|---------|-------------|
| `poll_interval` | `5` | Window title poll interval (seconds) |
| `clipboard_poll_interval` | `2` | Clipboard poll interval (seconds) |
| `max_clipboard_length` | `2000` | Max clipboard characters to store |
| `exclude_apps` | password managers | App names to skip entirely |
| `exclude_window_patterns` | sensitive words | Window title patterns to skip |
| `browser_history_on_export` | `true` | Import browser history when exporting |
| `hotkey` | `"ctrl+shift+F12"` | Global hotkey to stop recording |
| `tray_icon` | `true` | Show tray icon (requires pystray + Pillow) |
| `redact` | `true` | Redact sensitive values before storage |

---

## Converting a session log to a note

Use `session2note.py` to turn a session JSONL file into a structured Markdown
note using the same pipeline as `dump2note.py`.  It is called automatically
by `session_recorder.py export`, but can also be run directly.

### Quick start

```bash
# Export today's session (auto-detects tool, writes to notes/)
python session2note.py

# Preview without writing
python session2note.py --preview

# Export a specific date, include browser URLs
python session2note.py --date 2026-04-20 --include-urls

# Import fresh browser history and preview
python session2note.py --browser-history --preview

# Force a tool name
python session2note.py --tool nmap
```

### Options

```
  --date DATE           Date as YYYY-MM-DD (default: today)
  --tool TOOL           Force tool / session name
  --preview             Print the note without writing to disk
  --append              Append to an existing note instead of overwriting
  --no-redact           Disable automatic redaction
  --include-urls        Include browser URLs in the note
  --session-dir DIR     Directory containing session JSONL files
  --output-dir DIR      Root directory for notes (default: notes/)
  --browser-history     Import fresh browser history before generating note
  --history-since SECS  Seconds of browser history to import (default: 86400)
```

---

## Publishing notes to GitHub

Use `publish-lab-notes.sh` to convert a lab dump **and** commit/push the
result to GitHub in a single command.

### Requirements

- Python 3.10+ (for `dump2note.py`)
- Git with push access configured (SSH key, HTTPS credential helper, or a
  [personal access token](https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/managing-your-personal-access-tokens))

### Quick start

```bash
# Make executable (one-time setup)
chmod +x publish-lab-notes.sh

# Full pipeline – convert session.log, commit, and push
./publish-lab-notes.sh session.log --platform htb --lab "Lame"

# Fully non-interactive (great for shell aliases)
./publish-lab-notes.sh nmap.log --platform thm --lab "Nmap Room" \
    --tool nmap --date 2026-04-20 --yes

# Commit-only mode (when you already ran dump2note.py manually)
./publish-lab-notes.sh --platform htb --lab "Lame"

# Auto-convert from terminal history, then commit and push
./publish-lab-notes.sh --history --platform htb --lab "Lame"

# Local commit only – push later
./publish-lab-notes.sh session.log --no-push
```

### What it does

| Step | Description |
|------|-------------|
| **Pull** | `git pull --rebase` to sync with the remote before making changes |
| **Convert** | Runs `dump2note.py` on your dump file (skipped in commit-only mode) |
| **Stage** | `git add notes/` to stage all new and modified notes |
| **Confirm** | Shows staged files and commit message; prompts before proceeding |
| **Commit** | Creates a commit like `Add HTB lab notes: Lame [2026-04-20]` |
| **Push** | `git push` to publish to GitHub (skip with `--no-push`) |

### Options

```
Usage: publish-lab-notes.sh [DUMP_FILE] [OPTIONS]

  DUMP_FILE             Path to raw dump file. Omit to commit existing note changes.

Script options:
  --platform PLATFORM   Platform label (e.g. thm, htb, pwn.college)
  --lab LAB             Lab / room / challenge name (used in commit message)
  --no-push             Commit locally without pushing to remote
  -y, --yes             Skip confirmation prompt before committing
  -h, --help            Show this message and exit

Options forwarded to dump2note.py:
  --tool TOOL           Force tool name (skips auto-detection prompt)
  --date DATE           Force date as YYYY-MM-DD (default: today)
  --append              Append to an existing note instead of overwriting
  --no-redact           Disable automatic redaction of sensitive values
  --history             Auto-read terminal history and convert it
  --history-lines N     Number of recent history lines to ingest (default: 500)
  --output-dir DIR      Notes root directory (default: notes/)
```

> **Windows users:** Run the script inside [Git Bash](https://git-scm.com/downloads)
> or [WSL](https://learn.microsoft.com/en-us/windows/wsl/install).
