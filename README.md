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
