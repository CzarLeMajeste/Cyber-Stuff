#!/usr/bin/env python3
"""
dump2note.py – Convert a raw data dump into a structured cybersecurity note.

Usage
-----
    python dump2note.py [DUMP_FILE] [OPTIONS]

If DUMP_FILE is omitted the tool reads from stdin (finish with Ctrl-D on Unix
or Ctrl-Z + Enter on Windows).

Options
-------
    --tool TOOL         Force tool name (skips auto-detection)
    --date DATE         Force date as YYYY-MM-DD (default: today)
    --preview           Print the generated note; do NOT write to disk
    --append            Append to an existing note instead of overwriting
    --no-redact         Disable automatic redaction of sensitive values
    --history           Auto-read the current shell history and convert it
    --history-lines N   Number of recent history lines to ingest (default: 500)
    --output-dir DIR    Root directory for notes (default: notes/)
    --session           Read from the session-recorder JSONL log for --date
    --session-dir DIR   Session data directory (default: platform app-data path)
    --include-urls      Include browser URLs when reading a session JSONL file
    --help, -h          Show this help message

Examples
--------
    # Interactive – paste a dump, confirm tool/date, write note
    python dump2note.py

    # From file, preview only
    python dump2note.py examples/nmap-clean.txt --preview

    # From file, force tool + date, append to existing note
    python dump2note.py session.log --tool nmap --date 2026-04-17 --append

    # Pipe from clipboard / another command
    cat session.log | python dump2note.py --tool sqlmap

    # Auto-ingest your terminal session history
    python dump2note.py --history --history-lines 300

    # Convert today's session-recorder log into a note (includes timeline)
    python dump2note.py --session

    # Convert a specific date's session log, including browser URLs
    python dump2note.py --session --date 2026-04-20 --include-urls

    # Use a custom session data directory
    python dump2note.py --session --session-dir /mnt/logs/sessions --date 2026-04-20
"""

from __future__ import annotations

import argparse
import json
import os
import platform as _platform
import re
import sys
from datetime import date as _date
from pathlib import Path

# ---------------------------------------------------------------------------
# Session-recorder integration helpers
# ---------------------------------------------------------------------------

def _default_session_dir() -> Path:
    """Return the platform-appropriate session-logger data directory.

    Mirrors the path chosen by the Rust session-recorder binary:
      Linux   – $XDG_DATA_HOME/session-logger/sessions  (~/.local/share/…)
      macOS   – ~/Library/Application Support/session-logger/sessions
      Windows – %LOCALAPPDATA%/session-logger/sessions
    """
    system = _platform.system()
    if system == 'Windows':
        base = Path(os.environ.get('LOCALAPPDATA', '~')).expanduser()
    elif system == 'Darwin':
        base = Path('~/Library/Application Support').expanduser()
    else:
        xdg = os.environ.get('XDG_DATA_HOME', '')
        base = Path(xdg).expanduser() if xdg else Path('~/.local/share').expanduser()
    return base / 'session-logger' / 'sessions'


def read_session_jsonl(
    path: Path,
    include_urls: bool = False,
) -> tuple[str, list[str]]:
    """Read a session-recorder JSONL file and prepare it for the note pipeline.

    Returns
    -------
    text : str
        A plain-text representation of the session events suitable for
        ``normalize_lines`` / ``classify_lines`` (mirrors the Rust
        ``events_to_text`` function in ``notes.rs``).
    timeline : list[str]
        Human-readable window-focus entries (timestamped) for the optional
        **Session Timeline** section of the generated note.
    """
    text_lines: list[str] = []
    timeline: list[str] = []

    for raw_line in path.read_text(errors='replace').splitlines():
        raw_line = raw_line.strip()
        if not raw_line:
            continue
        try:
            ev = json.loads(raw_line)
        except json.JSONDecodeError:
            continue

        event_type = ev.get('type', '')
        data = ev.get('data', '').strip()
        ts = ev.get('ts', '')
        app = ev.get('app', '')

        if event_type == 'window':
            text_lines.append(f'# Window: {data}')
            label = f'[{ts}] {app}: {data}' if app else f'[{ts}] {data}'
            timeline.append(label)
        elif event_type == 'clipboard':
            if '\n' in data:
                text_lines.append(f'# Clipboard:\n{data}')
            elif data:
                text_lines.append(data)
        elif event_type == 'browser_url' and include_urls:
            text_lines.append(f'# URL: {data}')
        elif event_type == 'command':
            text_lines.append(f'$ {data}')
        elif event_type == 'system':
            text_lines.append(f'# [{data}]')

    return '\n'.join(text_lines), timeline


# ---------------------------------------------------------------------------
# Tool auto-detection – ordered from most specific to least specific
# ---------------------------------------------------------------------------
TOOL_SIGNATURES: list[tuple[str, str]] = [
    (r'\bnmap\b|Nmap scan report|PORT\s+STATE\s+SERVICE|Starting Nmap', 'nmap'),
    (r'\bmsfconsole\b|msf\s*[56]?\s*>|Metasploit|exploit\(|meterpreter\s*>', 'metasploit'),
    (r'Burp Suite|\bburp\b', 'burpsuite'),
    (r'\bsqlmap\b|testing for SQL injection', 'sqlmap'),
    (r'\bgobuster\b|Dir Mode:', 'gobuster'),
    (r'\bhydra\b|\[DATA\] attacking', 'hydra'),
    (r'\bnikto\b|Nikto v\d', 'nikto'),
    (r'\btshark\b|\bwireshark\b', 'wireshark'),
    (r'\bjohn\b|John the Ripper', 'john'),
    (r'\bhashcat\b', 'hashcat'),
    (r'\bdirb\b|DIRB v\d', 'dirb'),
    (r'\bffuf\b', 'ffuf'),
    (r'\bwfuzz\b', 'wfuzz'),
    (r'\bnetcat\b|\bnc\s+-[lnvup]', 'netcat'),
    (r'\bdirsearch\b', 'dirsearch'),
    (r'\benum4linux\b', 'enum4linux'),
    (r'\bsmbclient\b', 'smbclient'),
    (r'\bcrackmapexec\b|\bcme\b', 'crackmapexec'),
    (r'\bbloodhound\b|\bSharpHound\b', 'bloodhound'),
    (r'\bmimikatz\b', 'mimikatz'),
    (r'\blinpeas\b|PEASS', 'linpeas'),
    (r'\bwinpeas\b', 'winpeas'),
    (r'\bwpscan\b', 'wpscan'),
    (r'\baircrack-ng\b|\bairodump-ng\b', 'aircrack-ng'),
    (r'\bferoxbuster\b', 'feroxbuster'),
    (r'\bdig\b.*axfr|zone transfer', 'dig'),
    (r'\bpython.*http\.server\b|\bSimpleHTTP\b', 'python-http-server'),
    (r'\bcurl\b', 'curl'),
]

# ---------------------------------------------------------------------------
# Sensitive-value redaction patterns  (regex, replacement)
# ---------------------------------------------------------------------------
REDACT_PATTERNS: list[tuple[str, str]] = [
    # CLI password flags
    (r'(-p|--password|--pass)\s+\S+', r'\1 [REDACTED]'),
    # Key=value credential patterns
    (r'(password|passwd|pwd)\s*[=:]\s*\S+', r'\1=[REDACTED]'),
    # HTTP Authorization header values
    (r'(Authorization:\s*(?:Basic|Bearer)\s+)\S+', r'\1[REDACTED]'),
    # Generic API key / token / secret assignments
    (r'(api[_-]?key|apikey|token|secret|access[_-]?key)\s*[=:]\s*\S+', r'\1=[REDACTED]'),
    # JWT (three base64url-separated segments)
    (r'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+', '[JWT_REDACTED]'),
    # AWS-style access key IDs (20-char IDs starting with AKIA/ASIA)
    (r'(AKIA|ASIA)[A-Z0-9]{16}', '[AWS_KEY_REDACTED]'),
]

# ---------------------------------------------------------------------------
# Line-classification regexes
# ---------------------------------------------------------------------------
_CMD_PATTERNS = [
    r'^\s*[$#%>]\s+\S',                          # shell prompt lines
    r'^\s*(sudo|su|cd|ls|cat|echo|export|source|chmod|chown|mv|cp|rm|'
    r'mkdir|touch|wget|curl|python3?|perl|ruby|php|bash|sh|zsh|'
    r'pwsh|powershell)\b',
    r'^\s*(nmap|sqlmap|gobuster|hydra|nikto|ffuf|wfuzz|dirb|dirsearch|'
    r'john|hashcat|crackmapexec|smbclient|enum4linux|bloodhound|mimikatz|'
    r'feroxbuster|wpscan|aircrack-ng|airodump-ng|tshark|wireshark|'
    r'msfconsole|msfvenom)\b',
    r'^\s*(use |set |run$|exploit$|back$|sessions)',  # Metasploit console commands
    r'^\s*>?\s*nc\s+-',                           # netcat
]

_FINDING_PATTERNS = [
    r'\b\d+/tcp\s+(open|closed|filtered)\b',      # nmap port line
    r'\b(vulnerable|vuln|CVE-\d{4}-\d+)\b',
    r'\b(found|discovered|detected|identified)\b',
    r'\[\s*(\+|\*|!)\s*\]',                       # common tool output markers
    r'\b200\s+OK\b|HTTP/\d\.\d\s+\d{3}',
    r'\b(username|password|hash|credential).*:',
    r'\b(admin|root)\b.*\b(found|valid|correct|success)\b',
    r'(shell|meterpreter|session)\s*(gained|opened|\d+)',
    r'\bsql injection\b|\bxss\b|\blfi\b|\brfi\b|\bssrf\b|\brce\b',
]

_FOLLOWUP_PATTERNS = [
    r'\b(TODO|FIXME|NOTE|INVESTIGATE|CHECK|VERIFY|FOLLOW.?UP|TBD|REVISIT)\b',
    r'\?\s*$',                                    # lines ending in a question
    r'\b(need to|should|must|worth trying|next step)\b',
]


def _compile(patterns: list[str]) -> re.Pattern:
    return re.compile('|'.join(patterns), re.IGNORECASE)


CMD_RE = _compile(_CMD_PATTERNS)
FINDING_RE = _compile(_FINDING_PATTERNS)
FOLLOWUP_RE = _compile(_FOLLOWUP_PATTERNS)
DATE_RE = re.compile(r'\b(\d{4}[-/]\d{2}[-/]\d{2})\b|\b(\d{2}[-/]\d{2}[-/]\d{4})\b')

# ---------------------------------------------------------------------------
# Core helpers
# ---------------------------------------------------------------------------

def detect_tool(text: str) -> str | None:
    """Return the first matching tool name, or None."""
    for pattern, name in TOOL_SIGNATURES:
        if re.search(pattern, text, re.IGNORECASE):
            return name
    return None


def detect_date(text: str) -> str | None:
    """Extract the first date-like string from text (ISO or DD/MM/YYYY)."""
    m = DATE_RE.search(text)
    if not m:
        return None
    raw = m.group(1) or m.group(2)
    return raw.replace('/', '-')


def redact(text: str) -> str:
    """Apply all redaction patterns to a single line."""
    for pattern, replacement in REDACT_PATTERNS:
        text = re.sub(pattern, replacement, text, flags=re.IGNORECASE)
    return text


def read_terminal_history(max_lines: int) -> str:
    """Read the latest commands from the user's shell history file."""
    candidates: list[Path] = []
    histfile = os.environ.get('HISTFILE')
    if histfile:
        candidates.append(Path(histfile).expanduser())
    xdg_state_home = os.environ.get('XDG_STATE_HOME')
    if xdg_state_home:
        candidates.append(Path(xdg_state_home).expanduser() / 'bash' / 'history')
    candidates.extend([
        Path('~/.local/state/bash/history').expanduser(),     # XDG-style bash history
        Path('~/.bash_history').expanduser(),                 # bash default
        Path('~/.zsh_history').expanduser(),                  # zsh default
        Path('~/.local/share/fish/fish_history').expanduser(),  # fish standard
        Path('~/.config/fish/fish_history').expanduser(),       # fish legacy
    ])

    history_path = next((p for p in candidates if p.is_file()), None)
    if not history_path:
        raise FileNotFoundError(
            'Could not find a shell history file. Set/export HISTFILE or use DUMP_FILE/stdin instead.'
        )

    lines = history_path.read_text(errors='replace').splitlines()
    recent = lines[-max_lines:] if max_lines > 0 else lines
    # zsh history can include timestamp prefixes like ": 1713670709:0;command"
    cleaned = [re.sub(r'^:\s+\d+:\d+;', '', line) for line in recent]
    return '\n'.join(cleaned)


def normalize_lines(lines: list[str]) -> list[str]:
    """Deduplicate exact repeated lines and collapse runs of blank lines."""
    seen: set[str] = set()
    deduped: list[str] = []
    for raw in lines:
        line = raw.rstrip()
        if line not in seen:
            seen.add(line)
            deduped.append(line)

    # collapse consecutive blank lines into one
    result: list[str] = []
    prev_blank = False
    for line in deduped:
        is_blank = not line.strip()
        if is_blank and prev_blank:
            continue
        result.append(line)
        prev_blank = is_blank
    return result


def classify_lines(lines: list[str], do_redact: bool) -> dict[str, list[str]]:
    """Sort non-blank lines into buckets: commands, findings, followups, raw."""
    buckets: dict[str, list[str]] = {
        'commands': [],
        'findings': [],
        'followups': [],
        'raw': [],
    }
    for line in lines:
        stripped = line.strip()
        if not stripped:
            continue
        if do_redact:
            stripped = redact(stripped)
        # Priority: follow-up > command > finding > raw
        if FOLLOWUP_RE.search(stripped):
            buckets['followups'].append(stripped)
        elif CMD_RE.match(stripped):
            buckets['commands'].append(stripped)
        elif FINDING_RE.search(stripped):
            buckets['findings'].append(stripped)
        else:
            buckets['raw'].append(stripped)
    return buckets


def build_summary(buckets: dict[str, list[str]]) -> str:
    parts = []
    if buckets['commands']:
        parts.append(f"{len(buckets['commands'])} command(s) captured.")
    if buckets['findings']:
        parts.append(f"{len(buckets['findings'])} finding(s) identified.")
    if buckets['followups']:
        parts.append(f"{len(buckets['followups'])} follow-up item(s) noted.")
    return ' '.join(parts) if parts else 'No structured content detected from dump.'


def _fmt_list(items: list[str], fallback: str = 'None captured.') -> str:
    if not items:
        return f'- {fallback}'
    return '\n'.join(f'- {item}' for item in items)


def _fmt_task_list(items: list[str], fallback: str = 'None captured.') -> str:
    if not items:
        return f'- [ ] {fallback}'
    return '\n'.join(f'- [ ] {item}' for item in items)


def build_note(
    tool: str,
    date_str: str,
    buckets: dict[str, list[str]],
    timeline: list[str] | None = None,
) -> str:
    """Render a complete Obsidian-friendly Markdown note from classified buckets."""
    summary = build_summary(buckets)

    raw_section = ''
    if buckets['raw']:
        raw_section = '\n\n## Raw Notes\n\n' + _fmt_list(buckets['raw'])

    timeline_section = ''
    if timeline:
        timeline_section = '\n\n## Session Timeline\n\n' + _fmt_list(timeline)

    return (
        f'---\n'
        f'tool: {tool}\n'
        f'date: {date_str}\n'
        f'tags:\n'
        f'  - cyber\n'
        f'  - tool/{tool}\n'
        f'---\n\n'
        f'# {tool} Notes\n\n'
        f'- Tool: {tool}\n'
        f'- Date: {date_str}\n\n'
        f'## Summary\n\n'
        f'{summary}\n\n'
        f'## Commands / Steps\n\n'
        f'{_fmt_list(buckets["commands"])}\n\n'
        f'## Findings\n\n'
        f'{_fmt_list(buckets["findings"])}\n\n'
        f'## Follow-ups\n\n'
        f'{_fmt_task_list(buckets["followups"])}'
        f'{raw_section}'
        f'{timeline_section}\n'
    )

# ---------------------------------------------------------------------------
# User interaction helpers
# ---------------------------------------------------------------------------

def _ask(prompt: str, default: str = '') -> str:
    """Prompt the user and return their input, or default on empty/EOF."""
    try:
        val = input(prompt).strip()
        return val if val else default
    except (EOFError, KeyboardInterrupt):
        return default


def prompt_tool(detected: str | None) -> str:
    if detected:
        answer = _ask(
            f'Detected tool: "{detected}". Press Enter to confirm or type a name: ',
            detected,
        )
        return answer or detected
    return _ask('Could not detect tool automatically. Enter tool name: ', 'unknown')


def prompt_date(detected: str | None) -> str:
    today = _date.today().isoformat()
    if detected:
        answer = _ask(
            f'Detected date: "{detected}". Press Enter to confirm or type YYYY-MM-DD: ',
            detected,
        )
        return answer or detected
    return _ask(f'Enter date (YYYY-MM-DD) [default: {today}]: ', today) or today

# ---------------------------------------------------------------------------
# CLI argument parsing
# ---------------------------------------------------------------------------

def parse_args(argv: list[str]) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog='dump2note.py',
        description='Convert a raw data dump into a structured cybersecurity note.',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            'Examples:\n'
            '  python dump2note.py                              # interactive stdin\n'
            '  python dump2note.py session.log --preview        # preview only\n'
            '  python dump2note.py nmap.txt --tool nmap --date 2026-04-17\n'
            '  cat log.txt | python dump2note.py --tool sqlmap  # pipe input\n'
            '  python dump2note.py --history --history-lines 300 # auto history mode\n'
            '  python dump2note.py --session                    # today\'s session log\n'
            '  python dump2note.py --session --date 2026-04-20 --include-urls\n'
        ),
    )
    p.add_argument('dump_file', nargs='?', help='Path to raw dump file (default: stdin)')
    p.add_argument('--tool', help='Force tool name (skips auto-detection)')
    p.add_argument('--date', help='Force date as YYYY-MM-DD (default: today)')
    p.add_argument('--preview', action='store_true',
                   help='Print the generated note without writing to disk')
    p.add_argument('--append', action='store_true',
                   help='Append to an existing note instead of overwriting')
    p.add_argument('--no-redact', dest='no_redact', action='store_true',
                   help='Disable automatic redaction of sensitive values')
    p.add_argument('--history', action='store_true',
                   help='Auto-read the current shell history and convert it')
    p.add_argument('--history-lines', type=int, default=500,
                   help='How many recent history lines to ingest with --history (default: 500)')
    p.add_argument('--output-dir', dest='output_dir', default='notes',
                   help='Root directory for notes (default: notes/)')
    p.add_argument('--session', action='store_true',
                   help=(
                       'Read from the session-recorder JSONL log for --date '
                       '(or today). Looks in --session-dir / <YYYY> / <date>.jsonl.'
                   ))
    p.add_argument('--session-dir', dest='session_dir', default=None,
                   help=(
                       f'Session data directory '
                       f'(default: {_default_session_dir()})'
                   ))
    p.add_argument('--include-urls', dest='include_urls', action='store_true',
                   help='Include browser URLs when reading a session JSONL file')
    return p.parse_args(argv)

# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv if argv is not None else sys.argv[1:])

    # Validate mutually exclusive input modes
    input_modes = sum([bool(args.dump_file), args.history, args.session])
    if input_modes > 1:
        print('ERROR: Use at most one of DUMP_FILE, --history, or --session.', file=sys.stderr)
        return 1
    if args.history and args.history_lines <= 0:
        print('ERROR: --history-lines must be greater than 0.', file=sys.stderr)
        return 1
    if args.include_urls and not args.session:
        print('ERROR: --include-urls is only valid with --session.', file=sys.stderr)
        return 1

    timeline: list[str] = []  # populated when reading a session JSONL file

    # 1. Read raw input -------------------------------------------------------
    if args.session:
        session_dir = Path(args.session_dir) if args.session_dir else _default_session_dir()
        date_for_lookup = args.date or _date.today().isoformat()
        year = date_for_lookup[:4]
        session_path = session_dir / year / f'{date_for_lookup}.jsonl'
        if not session_path.exists():
            print(f'ERROR: Session file not found: {session_path}', file=sys.stderr)
            print('  Hint: start recording with: session-recorder start', file=sys.stderr)
            return 1
        try:
            raw_text, timeline = read_session_jsonl(session_path, include_urls=args.include_urls)
        except OSError as exc:
            print(f'ERROR: Could not read session file: {exc}', file=sys.stderr)
            return 1
    elif args.history:
        try:
            raw_text = read_terminal_history(args.history_lines)
        except FileNotFoundError as exc:
            print(f'ERROR: {exc}', file=sys.stderr)
            return 1
    elif args.dump_file:
        dump_path = Path(args.dump_file)
        if not dump_path.exists():
            print(f'ERROR: File not found: {dump_path}', file=sys.stderr)
            return 1
        raw_text = dump_path.read_text(errors='replace')
    else:
        if sys.stdin.isatty():
            print('Paste your dump below. Press Ctrl-D (Unix) or Ctrl-Z+Enter (Windows) when done.\n')
        raw_text = sys.stdin.read()

    if not raw_text.strip():
        print('ERROR: Empty input – nothing to convert.', file=sys.stderr)
        return 1

    lines = raw_text.splitlines()

    # 2. Detect / confirm tool and date ----------------------------------------
    detected_tool = args.tool or detect_tool(raw_text)
    detected_date = args.date or detect_date(raw_text)

    # Session and history modes are non-interactive by design
    interactive = (
        not args.session
        and not args.history
        and (sys.stdin.isatty() or bool(args.dump_file))
    )
    if interactive:
        tool = args.tool or prompt_tool(detected_tool)
        date_str = args.date or prompt_date(detected_date)
    else:
        # Non-interactive (session/history/piped) – use detected values or sensible defaults
        tool = detected_tool or ('session' if args.session else 'unknown')
        date_str = detected_date or (args.date or _date.today().isoformat())

    # Sanitize tool name for use in file path
    tool_slug = re.sub(r'[^\w.-]', '-', tool).lower().strip('-')

    # 3. Normalize + classify --------------------------------------------------
    normalized = normalize_lines(lines)
    buckets = classify_lines(normalized, do_redact=not args.no_redact)

    # 4. Build note ------------------------------------------------------------
    note_content = build_note(tool_slug, date_str, buckets, timeline=timeline or None)

    # 5. Preview mode ----------------------------------------------------------
    if args.preview:
        print(note_content)
        return 0

    # 6. Resolve output path ---------------------------------------------------
    year = date_str[:4]
    out_dir = Path(args.output_dir) / tool_slug / year
    out_dir.mkdir(parents=True, exist_ok=True)
    out_file = out_dir / f'{date_str}.md'

    # 7. Write / append --------------------------------------------------------
    if out_file.exists() and not args.append:
        if interactive:
            choice = _ask(
                f'\nFile already exists: {out_file}\n'
                '  [o] Overwrite  [a] Append  [q] Quit  [default: a]: ',
                'a',
            ).lower()
        else:
            choice = 'a'  # safe default in non-interactive mode

        if choice == 'q':
            print('Aborted.')
            return 0
        elif choice == 'o':
            out_file.write_text(note_content)
        else:
            with out_file.open('a') as fh:
                fh.write('\n\n---\n\n')
                fh.write(note_content)
    elif out_file.exists() and args.append:
        with out_file.open('a') as fh:
            fh.write('\n\n---\n\n')
            fh.write(note_content)
    else:
        out_file.write_text(note_content)

    print(f'Note saved: {out_file}')
    return 0


if __name__ == '__main__':
    sys.exit(main())
