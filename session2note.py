#!/usr/bin/env python3
"""
session2note.py – Convert a recorded desktop session into a structured note.

Reads a session JSONL file produced by session_recorder.py and converts it
into a Markdown note following the same format as dump2note.py.

Usage
-----
    python session2note.py                          # export today's session
    python session2note.py --date 2026-04-20        # export a specific date
    python session2note.py --preview                # preview without writing
    python session2note.py --tool nmap              # force tool/session name
    python session2note.py --include-urls           # include browser URLs

Options
-------
    --date DATE           Date to export as YYYY-MM-DD (default: today)
    --tool TOOL           Force tool name (skips auto-detection)
    --preview             Print the note without writing to disk
    --append              Append to an existing note instead of overwriting
    --no-redact           Disable automatic redaction
    --include-urls        Include browser URLs in the note (excluded by default)
    --session-dir DIR     Directory containing session JSONL files
    --output-dir DIR      Root directory for notes (default: notes/)
    --browser-history     Import fresh browser history before generating note
    --history-since SECS  Seconds of browser history to import (default: 86400)
    -h, --help            Show this help message

Examples
--------
    python session2note.py                              # export today
    python session2note.py --date 2026-04-20            # export specific date
    python session2note.py --preview                    # preview without saving
    python session2note.py --include-urls               # include browser URLs
    python session2note.py --browser-history --preview  # import fresh history
"""

from __future__ import annotations

import argparse
import importlib.util
import re
import sys
import time
from datetime import date as _date
from pathlib import Path

# ---------------------------------------------------------------------------
# Ensure same-directory imports work regardless of CWD
# ---------------------------------------------------------------------------
_SCRIPT_DIR = Path(__file__).resolve().parent
if str(_SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(_SCRIPT_DIR))


# ---------------------------------------------------------------------------
# Runtime module loaders (avoids hard coupling at import time)
# ---------------------------------------------------------------------------

def _load_module(name: str, path: Path):
    """Load a Python module from an absolute file path."""
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise ImportError(f'Cannot load module {name} from {path}')
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod   # register so dataclass & similar decorators work
    spec.loader.exec_module(mod)   # type: ignore[union-attr]
    return mod


def _get_dump2note():
    return _load_module('dump2note', _SCRIPT_DIR / 'dump2note.py')


def _get_session_recorder():
    return _load_module('session_recorder', _SCRIPT_DIR / 'session_recorder.py')


# ---------------------------------------------------------------------------
# Event → text conversion
# ---------------------------------------------------------------------------

def events_to_text(events: list, include_urls: bool = False) -> str:
    """Convert a list of EventRecord objects to a plain-text dump.

    The resulting text is compatible with dump2note's normalise/classify
    pipeline:
      - Window titles become comment-style headings that give context.
      - Single-line clipboard content is emitted bare so dump2note's
        classifier can identify it as a command, finding, or raw note
        without the ``$`` prefix biasing the result.
      - Multi-line clipboard content is emitted under a heading.
      - Browser URLs are optionally included as heading-style lines.
      - System events (start/stop markers) are included as headings.
    """
    lines: list[str] = []
    for ev in events:
        if ev.type == 'window':
            lines.append(f'# Window: {ev.data}')
        elif ev.type == 'clipboard':
            text = ev.data.strip()
            if '\n' in text:
                lines.append(f'# Clipboard:\n{text}')
            else:
                # Emit bare so dump2note's classifier decides the category:
                # shell commands match CMD_RE, port lines match FINDING_RE, etc.
                lines.append(text)
        elif ev.type == 'browser_url' and include_urls:
            lines.append(f'# URL: {ev.data}')
        elif ev.type == 'command':
            lines.append(f'$ {ev.data}')
        elif ev.type == 'system':
            lines.append(f'# [{ev.data}]')
        # 'browser_url' without include_urls: silently omit
    return '\n'.join(lines)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def parse_args(argv: list[str]) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog='session2note.py',
        description='Convert a recorded desktop session into a structured Markdown note.',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            'Examples:\n'
            '  python session2note.py                         # export today\n'
            '  python session2note.py --date 2026-04-20\n'
            '  python session2note.py --preview\n'
            '  python session2note.py --include-urls\n'
            '  python session2note.py --browser-history --preview\n'
        ),
    )
    p.add_argument('--date', help='Date as YYYY-MM-DD (default: today)')
    p.add_argument('--tool', help='Force tool / session name')
    p.add_argument('--preview', action='store_true',
                   help='Print the note without writing to disk')
    p.add_argument('--append', action='store_true',
                   help='Append to existing note instead of overwriting')
    p.add_argument('--no-redact', dest='no_redact', action='store_true',
                   help='Disable automatic redaction')
    p.add_argument('--include-urls', dest='include_urls', action='store_true',
                   help='Include browser URLs in the note (excluded by default)')
    p.add_argument('--session-dir',
                   help='Directory containing session JSONL files '
                        '(default: ~/.local/share/session-logger/sessions)')
    p.add_argument('--output-dir', dest='output_dir', default='notes',
                   help='Root directory for notes (default: notes/)')
    p.add_argument('--browser-history', dest='browser_history',
                   action='store_true',
                   help='Import fresh browser history before generating note')
    p.add_argument('--history-since', dest='history_since', type=int,
                   default=86400,
                   help='Seconds of browser history to import (default: 86400)')
    return p.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv if argv is not None else sys.argv[1:])
    date_str = args.date or _date.today().isoformat()

    # Load helper modules
    try:
        d2n = _get_dump2note()
        sr = _get_session_recorder()
    except Exception as exc:
        print(f'ERROR: Could not load helper modules: {exc}', file=sys.stderr)
        return 1

    # Resolve session directory
    session_dir = (
        Path(args.session_dir).expanduser()
        if args.session_dir
        else sr._DEFAULT_SESSION_DIR
    )
    store = sr.EventStore(session_dir)
    events = store.read(date_str)

    # Optionally import fresh browser history
    if args.browser_history:
        since = int(time.time()) - args.history_since
        browser_events = sr.import_browser_history(
            since_ts=since,
            do_redact=not args.no_redact,
        )
        events = browser_events + events

    if not events:
        print(f'No session events found for {date_str}.', file=sys.stderr)
        return 1

    # Convert events → text → dump2note pipeline
    raw_text = events_to_text(events, include_urls=args.include_urls)
    if not raw_text.strip():
        print('ERROR: No content could be extracted from session events.',
              file=sys.stderr)
        return 1

    lines = raw_text.splitlines()

    # Detect tool or fall back to 'session'
    tool = args.tool or d2n.detect_tool(raw_text) or 'session'
    tool_slug = re.sub(r'[^\w.-]', '-', tool).lower().strip('-')

    # Normalise + classify (reuse dump2note pipeline)
    do_redact = not args.no_redact
    normalized = d2n.normalize_lines(lines)
    buckets = d2n.classify_lines(normalized, do_redact=do_redact)

    # Build note content
    note_content = d2n.build_note(tool_slug, date_str, buckets)

    # Preview mode
    if args.preview:
        print(note_content)
        return 0

    # Resolve output path
    year = date_str[:4]
    out_dir = Path(args.output_dir) / tool_slug / year
    out_dir.mkdir(parents=True, exist_ok=True)
    out_file = out_dir / f'{date_str}.md'

    # Write / append
    if out_file.exists():
        with out_file.open('a') as fh:
            fh.write('\n\n---\n\n')
            fh.write(note_content)
    else:
        out_file.write_text(note_content)

    print(f'Note saved: {out_file}')
    return 0


if __name__ == '__main__':
    sys.exit(main())
