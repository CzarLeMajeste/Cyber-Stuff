# Cyber-Stuff

This repo contains all my Cybersecurity notes.

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
