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
    --output-dir DIR    Root directory for notes (default: notes/)
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
"""

from __future__ import annotations

import argparse
import re
import sys
from datetime import date as _date
from pathlib import Path

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


def build_note(tool: str, date_str: str, buckets: dict[str, list[str]]) -> str:
    """Render a complete Markdown note from classified buckets."""
    summary = build_summary(buckets)

    raw_section = ''
    if buckets['raw']:
        raw_section = '\n\n## Raw Notes\n\n' + _fmt_list(buckets['raw'])

    return (
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
        f'{_fmt_list(buckets["followups"])}'
        f'{raw_section}\n'
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
    p.add_argument('--output-dir', dest='output_dir', default='notes',
                   help='Root directory for notes (default: notes/)')
    return p.parse_args(argv)

# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv if argv is not None else sys.argv[1:])

    # 1. Read raw input -------------------------------------------------------
    if args.dump_file:
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

    interactive = sys.stdin.isatty() or bool(args.dump_file)
    if interactive:
        tool = args.tool or prompt_tool(detected_tool)
        date_str = args.date or prompt_date(detected_date)
    else:
        # Non-interactive (piped) – use detected values or sensible defaults
        tool = detected_tool or 'unknown'
        date_str = detected_date or _date.today().isoformat()

    # Sanitize tool name for use in file path
    tool_slug = re.sub(r'[^\w.-]', '-', tool).lower().strip('-')

    # 3. Normalize + classify --------------------------------------------------
    normalized = normalize_lines(lines)
    buckets = classify_lines(normalized, do_redact=not args.no_redact)

    # 4. Build note ------------------------------------------------------------
    note_content = build_note(tool_slug, date_str, buckets)

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
