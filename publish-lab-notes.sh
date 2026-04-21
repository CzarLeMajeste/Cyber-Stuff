#!/usr/bin/env bash
# publish-lab-notes.sh – Convert a lab dump into a structured note and push it
# to GitHub in a single step.
#
# Requires: Python 3.10+, git with push access configured.
# Run with --help for full usage.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$SCRIPT_DIR"

# ── Defaults ──────────────────────────────────────────────────────────────────
DUMP_FILE=""
PLATFORM=""
LAB=""
D2N_ARGS=()
OUTPUT_DIR="notes"
RUN_DUMP2NOTE=0
NO_PUSH=0
YES=0

# ── Usage ──────────────────────────────────────────────────────────────────────
usage() {
  cat <<'EOF'
Usage: publish-lab-notes.sh [DUMP_FILE] [OPTIONS]

Convert a lab dump into a structured note and push it to GitHub.

  DUMP_FILE             Path to a raw dump file (optional).
                        If omitted, stages and commits any new or modified
                        files already present in the notes/ directory.

Script options:
  --platform PLATFORM   Platform label for the commit message (e.g. thm, htb)
  --lab LAB             Lab / room / challenge name (used in commit message)
  --no-push             Commit locally without pushing to remote
  -y, --yes             Skip the confirmation prompt before committing
  -h, --help            Show this message and exit

Options forwarded to dump2note.py:
  --tool TOOL           Force tool name (skips auto-detection prompt)
  --date DATE           Force date as YYYY-MM-DD (default: today)
  --append              Append to an existing note instead of overwriting
  --no-redact           Disable automatic redaction of sensitive values
  --history             Auto-read terminal history and convert it
  --history-lines N     Number of recent history lines to ingest (default: 500)
  --output-dir DIR      Notes root directory (default: notes/)

Examples:
  # Full pipeline – convert session.log, commit, and push
  ./publish-lab-notes.sh session.log --platform htb --lab "Lame"

  # Fully non-interactive (great for shell aliases / automation)
  ./publish-lab-notes.sh nmap.log --platform thm --lab "Nmap Room" \
      --tool nmap --date 2026-04-20 --yes

  # Commit-only mode (after running dump2note.py manually)
  ./publish-lab-notes.sh --platform htb --lab "Lame"

  # Auto-convert from terminal history, then commit and push
  ./publish-lab-notes.sh --history --platform htb --lab "Lame"

  # Local commit only – push later
  ./publish-lab-notes.sh session.log --no-push
EOF
}

# ── Argument parsing ───────────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
  case "$1" in
    --platform) PLATFORM="$2"; shift 2 ;;
    --lab)      LAB="$2";      shift 2 ;;
    --no-push)  NO_PUSH=1;     shift   ;;
    -y|--yes)   YES=1;         shift   ;;
    -h|--help)  usage; exit 0          ;;
    # Value options forwarded to dump2note.py
    --tool|--date)
      D2N_ARGS+=("$1" "$2"); shift 2 ;;
    --history-lines)
      RUN_DUMP2NOTE=1
      D2N_ARGS+=("$1" "$2"); shift 2 ;;
    --output-dir)
      OUTPUT_DIR="$2"
      D2N_ARGS+=("$1" "$2"); shift 2 ;;
    # Flag options forwarded to dump2note.py
    --append|--no-redact|--history)
      [[ "$1" == "--history" ]] && RUN_DUMP2NOTE=1
      D2N_ARGS+=("$1"); shift ;;
    -*)
      echo "ERROR: Unknown option: $1" >&2
      usage >&2
      exit 1 ;;
    *)
      if [[ -z "$DUMP_FILE" ]]; then
        DUMP_FILE="$1"
      else
        echo "ERROR: Unexpected argument: $1" >&2
        exit 1
      fi
      shift ;;
  esac
done

# Resolve dump file to an absolute path before we cd to REPO_ROOT
if [[ -n "$DUMP_FILE" ]]; then
  DUMP_FILE="$(cd "$(dirname "$DUMP_FILE")" && pwd)/$(basename "$DUMP_FILE")"
  if [[ ! -f "$DUMP_FILE" ]]; then
    echo "ERROR: Dump file not found: $DUMP_FILE" >&2
    exit 1
  fi
fi

cd "$REPO_ROOT"

# ── Step 1: Pull latest changes ────────────────────────────────────────────────
echo "==> Pulling latest changes..."
git pull --rebase
echo ""

# ── Step 2: Convert dump (if a file was provided) ──────────────────────────────
if [[ -n "$DUMP_FILE" ]]; then
  echo "==> Converting dump to note..."
  if [[ ${#D2N_ARGS[@]} -gt 0 ]]; then
    python3 dump2note.py "$DUMP_FILE" "${D2N_ARGS[@]}"
  else
    python3 dump2note.py "$DUMP_FILE"
  fi
  echo ""
elif [[ $RUN_DUMP2NOTE -eq 1 ]]; then
  echo "==> Converting terminal history to note..."
  python3 dump2note.py "${D2N_ARGS[@]}"
  echo ""
fi

# ── Step 3: Detect changed note files ──────────────────────────────────────────
# git status --porcelain format: "XY path" (columns 1-2 = status flags, 3 = space, 4+ = path)
CHANGED_NOTES=$(git status --porcelain "$OUTPUT_DIR" 2>/dev/null | cut -c4- || true)

if [[ -z "$CHANGED_NOTES" ]]; then
  echo "No changes detected in $OUTPUT_DIR/ – nothing to commit."
  exit 0
fi

# ── Step 4: Stage changed note files ───────────────────────────────────────────
echo "==> Staging changed notes..."
git add "$OUTPUT_DIR"

if git diff --cached --quiet; then
  echo "Nothing staged – all changes may have already been committed."
  exit 0
fi

# ── Step 5: Build commit message ───────────────────────────────────────────────
# Derive the date from the first changed note's filename (expected: YYYY-MM-DD.md)
FIRST_NOTE=$(echo "$CHANGED_NOTES" | head -1)
NOTE_DATE=$(basename "$FIRST_NOTE" .md)
if [[ ! "$NOTE_DATE" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}$ ]]; then
  NOTE_DATE=$(date +%Y-%m-%d)
fi

COMMIT_MSG="Add"
if [[ -n "$PLATFORM" ]]; then
  PLATFORM_UPPER=$(printf '%s' "$PLATFORM" | tr '[:lower:]' '[:upper:]')
  COMMIT_MSG+=" ${PLATFORM_UPPER}"
fi
COMMIT_MSG+=" lab notes"
if [[ -n "$LAB" ]]; then
  COMMIT_MSG+=": ${LAB}"
fi
COMMIT_MSG+=" [${NOTE_DATE}]"

# ── Step 6: Show staged files and confirm ──────────────────────────────────────
echo ""
echo "Files to commit:"
git diff --cached --name-only | sed 's/^/  /'
echo ""
echo "Commit message: \"${COMMIT_MSG}\""
echo ""

if [[ $YES -eq 0 ]]; then
  read -r -p "Proceed? [Y/n] " REPLY
  REPLY="${REPLY:-y}"
  if [[ ! "$REPLY" =~ ^[Yy]$ ]]; then
    echo "Aborted. Run 'git reset HEAD -- ${OUTPUT_DIR}' to unstage."
    exit 0
  fi
fi

# ── Step 7: Commit ─────────────────────────────────────────────────────────────
git commit -m "$COMMIT_MSG"

# ── Step 8: Push ───────────────────────────────────────────────────────────────
if [[ $NO_PUSH -eq 0 ]]; then
  echo ""
  echo "==> Pushing to remote..."
  git push
  echo ""
  echo "Done! Note published to GitHub."
else
  echo ""
  echo "Done! Committed locally. Run 'git push' when ready."
fi
