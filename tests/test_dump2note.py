"""
tests/test_dump2note.py – Comprehensive test suite for dump2note.py.

Run with: pytest tests/test_dump2note.py -v
"""

from __future__ import annotations

import json
import os
import shutil
import sys
import tempfile
from pathlib import Path

import pytest

# Make the repo root importable so we can import dump2note directly.
_REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_REPO_ROOT))

import dump2note as d2n  # noqa: E402


# ── detect_tool ───────────────────────────────────────────────────────────────

class TestDetectTool:
    """Tests for detect_tool(): verify every tool signature fires correctly."""

    @pytest.mark.parametrize("text,expected", [
        # nmap
        ("Starting Nmap 7.94 scan...", "nmap"),
        ("Nmap scan report for 10.0.0.1", "nmap"),
        ("PORT   STATE SERVICE\n80/tcp open  http", "nmap"),
        # metasploit
        ("msf6 > use exploit/multi/handler", "metasploit"),
        ("meterpreter > getuid", "metasploit"),
        ("Metasploit Framework", "metasploit"),
        # burpsuite
        ("Burp Suite Professional v2023", "burpsuite"),
        # sqlmap
        ("sqlmap identified the following injection point", "sqlmap"),
        ("testing for SQL injection on parameter id", "sqlmap"),
        # gobuster
        ("gobuster dir -u http://example.com -w wordlist.txt", "gobuster"),
        ("Dir Mode:", "gobuster"),
        # hydra
        ("hydra -l admin -P pass.txt ssh://10.0.0.1", "hydra"),
        ("[DATA] attacking ftp://10.0.0.1:21/", "hydra"),
        # nikto
        ("nikto -h http://example.com", "nikto"),
        ("- Nikto v2.1.6", "nikto"),
        # wireshark / tshark
        ("tshark -i eth0 -w capture.pcap", "wireshark"),
        ("wireshark capture analysis", "wireshark"),
        # john
        ("john --wordlist=rockyou.txt hash.txt", "john"),
        ("John the Ripper password cracker", "john"),
        # hashcat
        ("hashcat -m 0 -a 0 hash.txt rockyou.txt", "hashcat"),
        # dirb
        ("dirb http://example.com", "dirb"),
        ("DIRB v2.22", "dirb"),
        # ffuf
        ("ffuf -u http://example.com/FUZZ -w wordlist", "ffuf"),
        # wfuzz
        ("wfuzz -c -z file,wordlist.txt http://example.com/FUZZ", "wfuzz"),
        # netcat
        ("nc -lvnp 4444", "netcat"),
        ("netcat -e /bin/bash 10.0.0.1 4444", "netcat"),
        # dirsearch
        ("dirsearch -u http://example.com", "dirsearch"),
        # enum4linux
        ("enum4linux -a 10.0.0.1", "enum4linux"),
        # smbclient
        ("smbclient //10.0.0.1/share -U admin", "smbclient"),
        # crackmapexec / cme
        ("crackmapexec smb 10.0.0.0/24", "crackmapexec"),
        ("cme smb 10.0.0.1 -u admin", "crackmapexec"),
        # bloodhound
        ("bloodhound-python -d domain.local", "bloodhound"),
        ("SharpHound.exe -c All", "bloodhound"),
        # mimikatz
        ("mimikatz # sekurlsa::logonpasswords", "mimikatz"),
        # linpeas
        ("linpeas.sh output", "linpeas"),
        ("PEASS-ng privilege escalation", "linpeas"),
        # winpeas
        ("winpeas.exe output", "winpeas"),
        # wpscan
        ("wpscan --url http://example.com", "wpscan"),
        # aircrack-ng
        ("aircrack-ng capture.cap -w rockyou.txt", "aircrack-ng"),
        ("airodump-ng wlan0mon", "aircrack-ng"),
        # feroxbuster
        ("feroxbuster -u http://example.com", "feroxbuster"),
        # dig / zone transfer
        ("dig axfr @10.0.0.1 domain.local", "dig"),
        ("zone transfer successful", "dig"),
        # python http server
        ("python3 -m http.server 8080", "python-http-server"),
        ("SimpleHTTP server started on port 8080", "python-http-server"),
        # curl
        ("curl -s http://example.com/api", "curl"),
    ])
    def test_tool_detected(self, text, expected):
        assert d2n.detect_tool(text) == expected

    def test_returns_none_for_unrecognised_text(self):
        assert d2n.detect_tool("Hello, world! No tools here.") is None

    def test_returns_none_for_empty_string(self):
        assert d2n.detect_tool("") is None

    def test_first_match_wins(self):
        # nmap appears before metasploit in TOOL_SIGNATURES, so nmap should win
        # when both are present (depends on ordering)
        result = d2n.detect_tool("Starting Nmap and msf6 >")
        assert result == "nmap"


# ── detect_date ───────────────────────────────────────────────────────────────

class TestDetectDate:
    def test_iso_date_detected(self):
        assert d2n.detect_date("Session from 2026-04-17") == "2026-04-17"

    def test_iso_date_with_slashes_detected(self):
        result = d2n.detect_date("Generated on 2026/04/17")
        assert result == "2026-04-17"

    def test_dd_mm_yyyy_detected(self):
        result = d2n.detect_date("Report date: 17/04/2026")
        assert result == "17-04-2026"

    def test_dd_mm_yyyy_with_dashes(self):
        result = d2n.detect_date("Dump created 17-04-2026")
        assert result == "17-04-2026"

    def test_returns_none_when_no_date(self):
        assert d2n.detect_date("no dates here") is None

    def test_returns_none_for_empty_string(self):
        assert d2n.detect_date("") is None

    def test_returns_first_date_in_text(self):
        result = d2n.detect_date("First: 2026-01-01, second: 2026-12-31")
        assert result == "2026-01-01"


# ── redact ────────────────────────────────────────────────────────────────────

class TestRedact:
    def test_password_flag_short(self):
        result = d2n.redact("hydra -l admin -p s3cr3t ssh://10.0.0.1")
        assert "s3cr3t" not in result
        assert "[REDACTED]" in result

    def test_password_flag_long(self):
        result = d2n.redact("script --password mysupersecret")
        assert "mysupersecret" not in result
        assert "[REDACTED]" in result

    def test_password_equals(self):
        result = d2n.redact("password=hunter2")
        assert "hunter2" not in result
        assert "[REDACTED]" in result

    def test_passwd_colon(self):
        result = d2n.redact("passwd: topsecret")
        assert "topsecret" not in result
        assert "[REDACTED]" in result

    def test_authorization_basic(self):
        result = d2n.redact("Authorization: Basic dXNlcjpwYXNz")
        assert "dXNlcjpwYXNz" not in result
        assert "[REDACTED]" in result

    def test_authorization_bearer(self):
        result = d2n.redact("Authorization: Bearer mytoken123")
        assert "mytoken123" not in result
        assert "[REDACTED]" in result

    def test_api_key(self):
        result = d2n.redact("api_key=abc123xyz")
        assert "abc123xyz" not in result
        assert "[REDACTED]" in result

    def test_token(self):
        result = d2n.redact("token=secrettoken")
        assert "secrettoken" not in result
        assert "[REDACTED]" in result

    def test_secret(self):
        result = d2n.redact("secret=mysecretvalue")
        assert "mysecretvalue" not in result
        assert "[REDACTED]" in result

    def test_jwt_redacted(self):
        jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
        # Use a context that does not trigger the 'token:' pattern so the JWT
        # pattern can match instead (REDACT_PATTERNS are applied in order and
        # the token pattern would otherwise consume the first segment).
        result = d2n.redact(f"Payload: {jwt}")
        assert "eyJhbGciOiJIUzI1NiJ9" not in result
        assert "[JWT_REDACTED]" in result

    def test_aws_access_key_redacted(self):
        result = d2n.redact("AWS Key: AKIAIOSFODNN7EXAMPLE")
        assert "AKIAIOSFODNN7EXAMPLE" not in result
        assert "[AWS_KEY_REDACTED]" in result

    def test_asia_key_redacted(self):
        result = d2n.redact("Key: ASIAIOSFODNN7EXAMPLE")
        assert "ASIAIOSFODNN7EXAMPLE" not in result
        assert "[AWS_KEY_REDACTED]" in result

    def test_no_false_positive_on_plain_text(self):
        plain = "nmap scan results for 10.0.0.1"
        assert d2n.redact(plain) == plain


# ── normalize_lines ───────────────────────────────────────────────────────────

class TestNormalizeLines:
    def test_deduplicates_exact_lines(self):
        lines = ["nmap -sV target", "nmap -sV target", "other"]
        result = d2n.normalize_lines(lines)
        assert result.count("nmap -sV target") == 1

    def test_collapses_consecutive_blank_lines(self):
        lines = ["a", "", "", "b"]
        result = d2n.normalize_lines(lines)
        blank_count = sum(1 for l in result if not l.strip())
        assert blank_count == 1

    def test_preserves_single_blank_between_content(self):
        lines = ["a", "", "b"]
        result = d2n.normalize_lines(lines)
        assert result == ["a", "", "b"]

    def test_strips_trailing_whitespace(self):
        lines = ["hello   "]
        result = d2n.normalize_lines(lines)
        assert result == ["hello"]

    def test_empty_list(self):
        assert d2n.normalize_lines([]) == []

    def test_all_duplicates(self):
        lines = ["same", "same", "same"]
        result = d2n.normalize_lines(lines)
        assert result == ["same"]

    def test_preserves_order(self):
        lines = ["first", "second", "third"]
        result = d2n.normalize_lines(lines)
        assert result == ["first", "second", "third"]


# ── classify_lines ────────────────────────────────────────────────────────────

class TestClassifyLines:
    def test_shell_prompt_classified_as_command(self):
        buckets = d2n.classify_lines(["$ nmap -sV 10.0.0.1"], do_redact=False)
        assert "$ nmap -sV 10.0.0.1" in buckets["commands"]
        assert not buckets["findings"]
        assert not buckets["followups"]

    def test_tool_name_at_start_classified_as_command(self):
        buckets = d2n.classify_lines(["nmap -sV target"], do_redact=False)
        assert any("nmap" in c for c in buckets["commands"])

    def test_nmap_port_classified_as_finding(self):
        buckets = d2n.classify_lines(["80/tcp open  http"], do_redact=False)
        assert any("80/tcp" in f for f in buckets["findings"])

    def test_cve_classified_as_finding(self):
        buckets = d2n.classify_lines(["CVE-2021-44228 vulnerability found"], do_redact=False)
        assert buckets["findings"]

    def test_todo_classified_as_followup(self):
        buckets = d2n.classify_lines(["TODO: check for LFI"], do_redact=False)
        assert buckets["followups"]

    def test_question_line_classified_as_followup(self):
        buckets = d2n.classify_lines(["Is port 8080 exploitable?"], do_redact=False)
        assert buckets["followups"]

    def test_need_to_classified_as_followup(self):
        buckets = d2n.classify_lines(["need to check SMB shares"], do_redact=False)
        assert buckets["followups"]

    def test_blank_lines_skipped(self):
        buckets = d2n.classify_lines(["", "   ", "\t"], do_redact=False)
        assert not any(buckets[k] for k in buckets)

    def test_unclassified_goes_to_raw(self):
        buckets = d2n.classify_lines(["just some random text here"], do_redact=False)
        assert "just some random text here" in buckets["raw"]

    def test_redact_flag_applied(self):
        buckets = d2n.classify_lines(["$ hydra -p s3cr3t target"], do_redact=True)
        for cmd in buckets["commands"]:
            assert "s3cr3t" not in cmd

    def test_followup_has_priority_over_command(self):
        # A line that would match both CMD and FOLLOWUP should go to followups
        buckets = d2n.classify_lines(["$ curl http://example.com  # TODO verify"], do_redact=False)
        # It matches FOLLOWUP pattern due to "TODO"
        assert buckets["followups"]

    def test_http_response_classified_as_finding(self):
        buckets = d2n.classify_lines(["HTTP/1.1 200 OK"], do_redact=False)
        assert buckets["findings"]


# ── build_summary ─────────────────────────────────────────────────────────────

class TestBuildSummary:
    def _buckets(self, commands=None, findings=None, followups=None, raw=None):
        return {
            "commands": commands or [],
            "findings": findings or [],
            "followups": followups or [],
            "raw": raw or [],
        }

    def test_empty_buckets_returns_fallback(self):
        summary = d2n.build_summary(self._buckets())
        assert "No structured content" in summary

    def test_counts_commands(self):
        b = self._buckets(commands=["cmd1", "cmd2"])
        assert "2 command(s)" in d2n.build_summary(b)

    def test_counts_findings(self):
        b = self._buckets(findings=["f1"])
        assert "1 finding(s)" in d2n.build_summary(b)

    def test_counts_followups(self):
        b = self._buckets(followups=["fu1", "fu2", "fu3"])
        assert "3 follow-up" in d2n.build_summary(b)

    def test_all_buckets_combined(self):
        b = self._buckets(
            commands=["c1"], findings=["f1"], followups=["fu1"]
        )
        summary = d2n.build_summary(b)
        assert "1 command(s)" in summary
        assert "1 finding(s)" in summary
        assert "1 follow-up" in summary


# ── _fmt_list / _fmt_task_list ────────────────────────────────────────────────

class TestFmtList:
    def test_empty_list_returns_fallback(self):
        assert d2n._fmt_list([]) == "- None captured."

    def test_custom_fallback(self):
        assert d2n._fmt_list([], fallback="Nothing here.") == "- Nothing here."

    def test_items_prefixed_with_dash(self):
        result = d2n._fmt_list(["item1", "item2"])
        assert result == "- item1\n- item2"


class TestFmtTaskList:
    def test_empty_list_returns_fallback(self):
        assert d2n._fmt_task_list([]) == "- [ ] None captured."

    def test_items_prefixed_with_checkbox(self):
        result = d2n._fmt_task_list(["task1", "task2"])
        assert result == "- [ ] task1\n- [ ] task2"


# ── build_note ────────────────────────────────────────────────────────────────

class TestBuildNote:
    def _empty_buckets(self):
        return {"commands": [], "findings": [], "followups": [], "raw": []}

    def test_contains_yaml_frontmatter(self):
        note = d2n.build_note("nmap", "2026-04-17", self._empty_buckets())
        assert "---" in note
        assert "tool: nmap" in note
        assert "date: 2026-04-17" in note

    def test_contains_required_sections(self):
        note = d2n.build_note("nmap", "2026-04-17", self._empty_buckets())
        assert "## Summary" in note
        assert "## Commands / Steps" in note
        assert "## Findings" in note
        assert "## Follow-ups" in note

    def test_raw_section_included_when_present(self):
        buckets = self._empty_buckets()
        buckets["raw"] = ["Some raw note"]
        note = d2n.build_note("nmap", "2026-04-17", buckets)
        assert "## Raw Notes" in note
        assert "Some raw note" in note

    def test_raw_section_absent_when_empty(self):
        note = d2n.build_note("nmap", "2026-04-17", self._empty_buckets())
        assert "## Raw Notes" not in note

    def test_timeline_section_included(self):
        note = d2n.build_note(
            "nmap", "2026-04-17", self._empty_buckets(),
            timeline=["[10:00] Firefox: Google"]
        )
        assert "## Session Timeline" in note
        assert "Firefox" in note

    def test_timeline_section_absent_when_not_provided(self):
        note = d2n.build_note("nmap", "2026-04-17", self._empty_buckets())
        assert "## Session Timeline" not in note

    def test_screenshots_section_included(self):
        note = d2n.build_note(
            "nmap", "2026-04-17", self._empty_buckets(),
            images=["![recon](assets/recon.png)"]
        )
        assert "## Screenshots" in note
        assert "![recon]" in note

    def test_screenshots_section_absent_when_not_provided(self):
        note = d2n.build_note("nmap", "2026-04-17", self._empty_buckets())
        assert "## Screenshots" not in note

    def test_tags_contain_tool(self):
        note = d2n.build_note("sqlmap", "2026-04-17", self._empty_buckets())
        assert "tool/sqlmap" in note

    def test_commands_listed(self):
        buckets = self._empty_buckets()
        buckets["commands"] = ["nmap -sV target", "curl http://example.com"]
        note = d2n.build_note("nmap", "2026-04-17", buckets)
        assert "nmap -sV target" in note
        assert "curl http://example.com" in note


# ── read_session_jsonl ────────────────────────────────────────────────────────

class TestReadSessionJsonl:
    def _write_jsonl(self, tmp_path, events):
        path = tmp_path / "session.jsonl"
        with path.open("w") as fh:
            for ev in events:
                fh.write(json.dumps(ev) + "\n")
        return path

    def test_window_events_appear_in_text_and_timeline(self, tmp_path):
        path = self._write_jsonl(tmp_path, [
            {"type": "window", "data": "Firefox", "ts": "2026-04-17T10:00:00Z", "app": "firefox"},
        ])
        text, timeline = d2n.read_session_jsonl(path)
        assert "# Window: Firefox" in text
        assert any("Firefox" in t for t in timeline)

    def test_command_events_appear_as_dollar_prefix(self, tmp_path):
        path = self._write_jsonl(tmp_path, [
            {"type": "command", "data": "nmap -sV 10.0.0.1", "ts": "T", "app": ""},
        ])
        text, timeline = d2n.read_session_jsonl(path)
        assert "$ nmap -sV 10.0.0.1" in text

    def test_clipboard_single_line_appears_as_plain(self, tmp_path):
        path = self._write_jsonl(tmp_path, [
            {"type": "clipboard", "data": "10.0.0.1", "ts": "T", "app": ""},
        ])
        text, _ = d2n.read_session_jsonl(path)
        assert "10.0.0.1" in text
        assert "# Clipboard:" not in text

    def test_clipboard_multiline_uses_header(self, tmp_path):
        path = self._write_jsonl(tmp_path, [
            {"type": "clipboard", "data": "line1\nline2", "ts": "T", "app": ""},
        ])
        text, _ = d2n.read_session_jsonl(path)
        assert "# Clipboard:" in text

    def test_browser_url_excluded_by_default(self, tmp_path):
        path = self._write_jsonl(tmp_path, [
            {"type": "browser_url", "data": "https://example.com", "ts": "T", "app": ""},
        ])
        text, _ = d2n.read_session_jsonl(path)
        assert "https://example.com" not in text

    def test_browser_url_included_when_flag_set(self, tmp_path):
        path = self._write_jsonl(tmp_path, [
            {"type": "browser_url", "data": "https://example.com", "ts": "T", "app": ""},
        ])
        text, _ = d2n.read_session_jsonl(path, include_urls=True)
        assert "# URL: https://example.com" in text

    def test_system_events_formatted(self, tmp_path):
        path = self._write_jsonl(tmp_path, [
            {"type": "system", "data": "Recording started", "ts": "T", "app": ""},
        ])
        text, _ = d2n.read_session_jsonl(path)
        assert "# [Recording started]" in text

    def test_invalid_json_lines_skipped(self, tmp_path):
        path = tmp_path / "session.jsonl"
        path.write_text('{"type":"command","data":"ok","ts":"T","app":""}\nnot-json\n')
        text, _ = d2n.read_session_jsonl(path)
        assert "$ ok" in text

    def test_empty_lines_skipped(self, tmp_path):
        path = tmp_path / "session.jsonl"
        path.write_text('\n\n{"type":"command","data":"ls","ts":"T","app":""}\n\n')
        text, _ = d2n.read_session_jsonl(path)
        assert "$ ls" in text

    def test_timeline_includes_app_when_present(self, tmp_path):
        path = self._write_jsonl(tmp_path, [
            {"type": "window", "data": "My Page", "ts": "2026-04-17T10:00:00Z", "app": "firefox"},
        ])
        _, timeline = d2n.read_session_jsonl(path)
        assert any("firefox" in t for t in timeline)

    def test_timeline_omits_app_when_absent(self, tmp_path):
        path = self._write_jsonl(tmp_path, [
            {"type": "window", "data": "My Page", "ts": "2026-04-17T10:00:00Z", "app": ""},
        ])
        _, timeline = d2n.read_session_jsonl(path)
        assert timeline[0] == "[2026-04-17T10:00:00Z] My Page"


# ── read_terminal_history ─────────────────────────────────────────────────────

class TestReadTerminalHistory:
    def test_reads_from_histfile_env(self, tmp_path, monkeypatch):
        hist = tmp_path / "hist"
        hist.write_text("cmd1\ncmd2\ncmd3\n")
        monkeypatch.setenv("HISTFILE", str(hist))
        result = d2n.read_terminal_history(500)
        assert "cmd1" in result
        assert "cmd3" in result

    def test_max_lines_respected(self, tmp_path, monkeypatch):
        hist = tmp_path / "hist"
        hist.write_text("\n".join(f"cmd{i}" for i in range(100)) + "\n")
        monkeypatch.setenv("HISTFILE", str(hist))
        result = d2n.read_terminal_history(10)
        lines = [l for l in result.splitlines() if l.strip()]
        assert len(lines) == 10
        # Should be the last 10
        assert "cmd99" in result

    def test_zsh_timestamp_prefix_stripped(self, tmp_path, monkeypatch):
        hist = tmp_path / "hist"
        hist.write_text(": 1713670709:0;nmap -sV target\n")
        monkeypatch.setenv("HISTFILE", str(hist))
        result = d2n.read_terminal_history(500)
        assert ": 1713670709:0;" not in result
        assert "nmap -sV target" in result

    def test_raises_when_no_history_file_found(self, tmp_path, monkeypatch):
        monkeypatch.delenv("HISTFILE", raising=False)
        monkeypatch.delenv("XDG_STATE_HOME", raising=False)
        # Point home to an empty tmp dir so no default files exist
        monkeypatch.setenv("HOME", str(tmp_path))
        with pytest.raises(FileNotFoundError):
            d2n.read_terminal_history(500)


# ── _copy_images ──────────────────────────────────────────────────────────────

class TestCopyImages:
    def test_copies_file_to_assets_dir(self, tmp_path):
        src = tmp_path / "recon.png"
        src.write_bytes(b"\x89PNG")
        assets_dir = tmp_path / "notes" / "nmap" / "2026" / "assets"

        refs = d2n._copy_images([src], assets_dir)

        assert (assets_dir / "recon.png").exists()
        assert len(refs) == 1
        assert "recon" in refs[0]

    def test_creates_assets_dir_if_missing(self, tmp_path):
        src = tmp_path / "shot.png"
        src.write_bytes(b"data")
        assets_dir = tmp_path / "new" / "assets"

        d2n._copy_images([src], assets_dir)

        assert assets_dir.is_dir()

    def test_returns_markdown_image_refs(self, tmp_path):
        src = tmp_path / "screen.jpg"
        src.write_bytes(b"data")
        assets_dir = tmp_path / "assets"

        refs = d2n._copy_images([src], assets_dir)

        assert refs[0].startswith("![screen]")

    def test_multiple_images_all_copied(self, tmp_path):
        images = []
        for name in ["a.png", "b.png", "c.png"]:
            p = tmp_path / name
            p.write_bytes(b"x")
            images.append(p)
        assets_dir = tmp_path / "assets"

        refs = d2n._copy_images(images, assets_dir)

        assert len(refs) == 3
        for name in ["a.png", "b.png", "c.png"]:
            assert (assets_dir / name).exists()

    def test_overwrites_existing_file(self, tmp_path):
        src = tmp_path / "recon.png"
        src.write_bytes(b"new content")
        assets_dir = tmp_path / "assets"
        assets_dir.mkdir()
        (assets_dir / "recon.png").write_bytes(b"old content")

        d2n._copy_images([src], assets_dir)

        assert (assets_dir / "recon.png").read_bytes() == b"new content"


# ── parse_args ────────────────────────────────────────────────────────────────

class TestParseArgs:
    def test_defaults(self):
        args = d2n.parse_args([])
        assert args.dump_file is None
        assert args.tool is None
        assert args.date is None
        assert not args.preview
        assert not args.append
        assert not args.no_redact
        assert not args.history
        assert args.history_lines == 500
        assert args.output_dir == "notes"
        assert not args.session
        assert args.session_dir is None
        assert not args.include_urls
        assert args.images == []

    def test_preview_flag(self):
        args = d2n.parse_args(["--preview"])
        assert args.preview

    def test_append_flag(self):
        args = d2n.parse_args(["--append"])
        assert args.append

    def test_no_redact_flag(self):
        args = d2n.parse_args(["--no-redact"])
        assert args.no_redact

    def test_tool_option(self):
        args = d2n.parse_args(["--tool", "nmap"])
        assert args.tool == "nmap"

    def test_date_option(self):
        args = d2n.parse_args(["--date", "2026-04-17"])
        assert args.date == "2026-04-17"

    def test_history_flag(self):
        args = d2n.parse_args(["--history"])
        assert args.history

    def test_history_lines_option(self):
        args = d2n.parse_args(["--history", "--history-lines", "200"])
        assert args.history_lines == 200

    def test_output_dir_option(self):
        args = d2n.parse_args(["--output-dir", "/tmp/notes"])
        assert args.output_dir == "/tmp/notes"

    def test_session_flag(self):
        args = d2n.parse_args(["--session"])
        assert args.session

    def test_session_dir_option(self):
        args = d2n.parse_args(["--session", "--session-dir", "/tmp/sessions"])
        assert args.session_dir == "/tmp/sessions"

    def test_include_urls_flag(self):
        args = d2n.parse_args(["--session", "--include-urls"])
        assert args.include_urls

    def test_images_option(self):
        args = d2n.parse_args(["--images", "a.png", "b.jpg"])
        assert args.images == ["a.png", "b.jpg"]

    def test_dump_file_positional(self):
        args = d2n.parse_args(["session.log"])
        assert args.dump_file == "session.log"


# ── main() integration – argument validation paths ────────────────────────────

class TestMainValidation:
    """Test that main() returns error codes for invalid argument combinations."""

    def test_mutual_exclusion_dump_file_and_history(self, tmp_path):
        dump = tmp_path / "dump.txt"
        dump.write_text("content")
        rc = d2n.main([str(dump), "--history"])
        assert rc == 1

    def test_mutual_exclusion_dump_file_and_session(self, tmp_path):
        dump = tmp_path / "dump.txt"
        dump.write_text("content")
        rc = d2n.main([str(dump), "--session"])
        assert rc == 1

    def test_mutual_exclusion_history_and_session(self):
        rc = d2n.main(["--history", "--session"])
        assert rc == 1

    def test_history_lines_zero_is_error(self):
        rc = d2n.main(["--history", "--history-lines", "0"])
        assert rc == 1

    def test_include_urls_without_session_is_error(self, tmp_path):
        dump = tmp_path / "dump.txt"
        dump.write_text("content")
        rc = d2n.main([str(dump), "--include-urls"])
        assert rc == 1

    def test_missing_dump_file_is_error(self):
        rc = d2n.main(["/nonexistent/path/dump.txt"])
        assert rc == 1

    def test_empty_input_is_error(self, tmp_path):
        dump = tmp_path / "empty.txt"
        dump.write_text("   \n  \n")
        rc = d2n.main([str(dump)])
        assert rc == 1

    def test_missing_image_file_is_error(self, tmp_path):
        dump = tmp_path / "dump.txt"
        dump.write_text("nmap -sV target")
        rc = d2n.main([str(dump), "--images", "/nonexistent/image.png"])
        assert rc == 1

    def test_preview_mode_returns_zero(self, tmp_path, capsys):
        dump = tmp_path / "dump.txt"
        dump.write_text("nmap -sV 10.0.0.1\n80/tcp open http")
        rc = d2n.main([str(dump), "--tool", "nmap", "--date", "2026-04-17", "--preview"])
        assert rc == 0
        captured = capsys.readouterr()
        assert "nmap Notes" in captured.out

    def test_write_note_to_disk(self, tmp_path):
        dump = tmp_path / "dump.txt"
        dump.write_text("nmap -sV 10.0.0.1\n80/tcp open http")
        outdir = tmp_path / "output"
        rc = d2n.main([
            str(dump), "--tool", "nmap", "--date", "2026-04-17",
            "--output-dir", str(outdir),
        ])
        assert rc == 0
        note_path = outdir / "nmap" / "2026" / "2026-04-17.md"
        assert note_path.exists()
        content = note_path.read_text()
        assert "nmap Notes" in content

    def test_session_mode_with_invalid_date(self, tmp_path):
        rc = d2n.main(["--session", "--date", "not-a-date", "--session-dir", str(tmp_path)])
        assert rc == 1

    def test_session_mode_missing_file(self, tmp_path):
        rc = d2n.main(["--session", "--date", "2026-04-17", "--session-dir", str(tmp_path)])
        assert rc == 1


# ── _default_session_dir ──────────────────────────────────────────────────────

class TestDefaultSessionDir:
    def test_returns_path(self):
        path = d2n._default_session_dir()
        assert isinstance(path, Path)
        assert "session-logger" in str(path)
        assert "sessions" in str(path)


# ── tool_slug (via main / build_note indirectly) ──────────────────────────────

class TestToolSlugViaMain:
    """Verify that special characters in tool names are sanitised."""

    def test_note_uses_slug_as_filename(self, tmp_path):
        dump = tmp_path / "dump.txt"
        dump.write_text("aircrack-ng capture.cap")
        outdir = tmp_path / "out"
        rc = d2n.main([
            str(dump), "--tool", "aircrack-ng", "--date", "2026-04-17",
            "--output-dir", str(outdir),
        ])
        assert rc == 0
        # The tool name contains a hyphen which is allowed in slugs
        note_path = outdir / "aircrack-ng" / "2026" / "2026-04-17.md"
        assert note_path.exists()
