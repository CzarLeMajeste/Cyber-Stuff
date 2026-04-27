// notes.rs – Note generation pipeline (reimplements dump2note.py in Rust).
//
// Tool detection, redaction, line normalisation/classification, and Markdown
// rendering are all handled here so the binary is fully self-contained.

use crate::event::EventRecord;
use regex::{Regex, RegexSet};
use std::collections::HashSet;
use std::sync::OnceLock;

// ── Static compiled regex sets ─────────────────────────────────────────────

static CMD_SET: OnceLock<RegexSet> = OnceLock::new();
static FINDING_SET: OnceLock<RegexSet> = OnceLock::new();
static FOLLOWUP_SET: OnceLock<RegexSet> = OnceLock::new();
static REDACT_VEC: OnceLock<Vec<(Regex, &'static str)>> = OnceLock::new();

fn cmd_set() -> &'static RegexSet {
    CMD_SET.get_or_init(|| {
        RegexSet::new([
            r"(?i)^\s*[$#%>]\s+\S",
            r"(?i)^\s*(sudo|su|cd|ls|cat|echo|export|source|chmod|chown|mv|cp|rm|mkdir|touch|wget|curl|python3?|perl|ruby|php|bash|sh|zsh|pwsh|powershell)\b",
            r"(?i)^\s*(nmap|sqlmap|gobuster|hydra|nikto|ffuf|wfuzz|dirb|dirsearch|john|hashcat|crackmapexec|smbclient|enum4linux|bloodhound|mimikatz|feroxbuster|wpscan|aircrack-ng|airodump-ng|tshark|wireshark|msfconsole|msfvenom)\b",
            r"(?i)^\s*(use |set |run$|exploit$|back$|sessions)",
            r"(?i)^\s*>?\s*nc\s+-",
        ]).unwrap()
    })
}

fn finding_set() -> &'static RegexSet {
    FINDING_SET.get_or_init(|| {
        RegexSet::new([
            r"\b\d+/tcp\s+(open|closed|filtered)\b",
            r"(?i)\b(vulnerable|vuln|CVE-\d{4}-\d+)\b",
            r"(?i)\b(found|discovered|detected|identified)\b",
            r"\[\s*[+*!]\s*\]",
            r"(?i)\b200\s+OK\b|HTTP/\d\.\d\s+\d{3}",
            r"(?i)\b(username|password|hash|credential).*:",
            r"(?i)\b(admin|root)\b.*\b(found|valid|correct|success)\b",
            r"(?i)(shell|meterpreter|session)\s*(gained|opened|\d+)",
            r"(?i)\bsql injection\b|\bxss\b|\blfi\b|\brfi\b|\bssrf\b|\brce\b",
        ]).unwrap()
    })
}

fn followup_set() -> &'static RegexSet {
    FOLLOWUP_SET.get_or_init(|| {
        RegexSet::new([
            r"(?i)\b(TODO|FIXME|NOTE|INVESTIGATE|CHECK|VERIFY|FOLLOW.?UP|TBD|REVISIT)\b",
            r"\?\s*$",
            r"(?i)\b(need to|should|must|worth trying|next step)\b",
        ]).unwrap()
    })
}

fn redact_vec() -> &'static Vec<(Regex, &'static str)> {
    REDACT_VEC.get_or_init(|| {
        vec![
            (Regex::new(r"(?i)(-p|--password|--pass)\s+\S+").unwrap(),
             "$1 [REDACTED]"),
            (Regex::new(r"(?i)(password|passwd|pwd)\s*[=:]\s*\S+").unwrap(),
             "$1=[REDACTED]"),
            (Regex::new(r"(?i)(Authorization:\s*(?:Basic|Bearer)\s+)\S+").unwrap(),
             "${1}[REDACTED]"),
            (Regex::new(r"(?i)(api[_\-]?key|apikey|token|secret|access[_\-]?key)\s*[=:]\s*\S+").unwrap(),
             "$1=[REDACTED]"),
            (Regex::new(r"eyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+").unwrap(),
             "[JWT_REDACTED]"),
            (Regex::new(r"(AKIA|ASIA)[A-Z0-9]{16}").unwrap(),
             "[AWS_KEY_REDACTED]"),
        ]
    })
}

// ── Tool signatures ────────────────────────────────────────────────────────

const TOOL_SIGNATURES: &[(&str, &str)] = &[
    (r"(?i)\bnmap\b|Nmap scan report|PORT\s+STATE\s+SERVICE|Starting Nmap", "nmap"),
    (r"(?i)\bmsfconsole\b|msf\s*[56]?\s*>|Metasploit|exploit\(|meterpreter\s*>", "metasploit"),
    (r"(?i)Burp Suite|\bburp\b", "burpsuite"),
    (r"(?i)\bsqlmap\b|testing for SQL injection", "sqlmap"),
    (r"(?i)\bgobuster\b|Dir Mode:", "gobuster"),
    (r"(?i)\bhydra\b|\[DATA\] attacking", "hydra"),
    (r"(?i)\bnikto\b|Nikto v\d", "nikto"),
    (r"(?i)\btshark\b|\bwireshark\b", "wireshark"),
    (r"(?i)\bjohn\b|John the Ripper", "john"),
    (r"(?i)\bhashcat\b", "hashcat"),
    (r"(?i)\bdirb\b|DIRB v\d", "dirb"),
    (r"(?i)\bffuf\b", "ffuf"),
    (r"(?i)\bwfuzz\b", "wfuzz"),
    (r"(?i)\bnetcat\b|\bnc\s+-[lnvup]", "netcat"),
    (r"(?i)\bdirsearch\b", "dirsearch"),
    (r"(?i)\benum4linux\b", "enum4linux"),
    (r"(?i)\bsmbclient\b", "smbclient"),
    (r"(?i)\bcrackmapexec\b|\bcme\b", "crackmapexec"),
    (r"(?i)\bbloodhound\b|\bSharpHound\b", "bloodhound"),
    (r"(?i)\bmimikatz\b", "mimikatz"),
    (r"(?i)\blinpeas\b|PEASS", "linpeas"),
    (r"(?i)\bwinpeas\b", "winpeas"),
    (r"(?i)\bwpscan\b", "wpscan"),
    (r"(?i)\baircrack-ng\b|\bairodump-ng\b", "aircrack-ng"),
    (r"(?i)\bferoxbuster\b", "feroxbuster"),
    (r"(?i)\bdig\b.*axfr|zone transfer", "dig"),
    (r"(?i)\bpython.*http\.server\b|\bSimpleHTTP\b", "python-http-server"),
    (r"(?i)\bcurl\b", "curl"),
];

// ── Public helpers ─────────────────────────────────────────────────────────

pub fn detect_tool(text: &str) -> Option<&'static str> {
    for (pat, name) in TOOL_SIGNATURES {
        if let Ok(re) = Regex::new(pat) {
            if re.is_match(text) {
                return Some(name);
            }
        }
    }
    None
}

pub fn redact_text(text: &str) -> String {
    let mut out = text.to_string();
    for (re, repl) in redact_vec() {
        out = re.replace_all(&out, *repl).to_string();
    }
    out
}

pub fn normalize_lines(lines: &[String]) -> Vec<String> {
    let mut seen = HashSet::new();
    let mut deduped = Vec::new();
    for line in lines {
        let t = line.trim_end().to_string();
        if seen.insert(t.clone()) {
            deduped.push(t);
        }
    }
    let mut result = Vec::new();
    let mut prev_blank = false;
    for line in deduped {
        let blank = line.trim().is_empty();
        if blank && prev_blank {
            continue;
        }
        result.push(line);
        prev_blank = blank;
    }
    result
}

#[derive(Default)]
pub struct Buckets {
    pub commands: Vec<String>,
    pub findings: Vec<String>,
    pub followups: Vec<String>,
    pub raw: Vec<String>,
}

pub fn classify_lines(lines: &[String], do_redact: bool) -> Buckets {
    let mut b = Buckets::default();
    for line in lines {
        let stripped = line.trim();
        if stripped.is_empty() {
            continue;
        }
        let text = if do_redact { redact_text(stripped) } else { stripped.to_string() };
        if followup_set().is_match(&text) {
            b.followups.push(text);
        } else if cmd_set().is_match(&text) {
            b.commands.push(text);
        } else if finding_set().is_match(&text) {
            b.findings.push(text);
        } else {
            b.raw.push(text);
        }
    }
    b
}

fn fmt_list(items: &[String], fallback: &str) -> String {
    if items.is_empty() {
        format!("- {fallback}")
    } else {
        items.iter().map(|i| format!("- {i}")).collect::<Vec<_>>().join("\n")
    }
}

fn fmt_task_list(items: &[String], fallback: &str) -> String {
    if items.is_empty() {
        format!("- [ ] {fallback}")
    } else {
        items.iter().map(|i| format!("- [ ] {i}")).collect::<Vec<_>>().join("\n")
    }
}

fn build_summary(b: &Buckets) -> String {
    let mut parts = Vec::new();
    if !b.commands.is_empty() {
        parts.push(format!("{} command(s) captured.", b.commands.len()));
    }
    if !b.findings.is_empty() {
        parts.push(format!("{} finding(s) identified.", b.findings.len()));
    }
    if !b.followups.is_empty() {
        parts.push(format!("{} follow-up item(s) noted.", b.followups.len()));
    }
    if parts.is_empty() {
        "No structured content detected from session.".to_string()
    } else {
        parts.join(" ")
    }
}

pub fn build_note(tool: &str, date_str: &str, b: &Buckets) -> String {
    let summary = build_summary(b);
    let raw_section = if b.raw.is_empty() {
        String::new()
    } else {
        format!("\n\n## Raw Notes\n\n{}", fmt_list(&b.raw, "None captured."))
    };
    format!(
        "---\ntool: {tool}\ndate: {date_str}\ntags:\n  - cyber\n  - tool/{tool}\n---\n\n\
# {tool} Notes\n\n- Tool: {tool}\n- Date: {date_str}\n\n\
## Summary\n\n{summary}\n\n\
## Commands / Steps\n\n{}\n\n\
## Findings\n\n{}\n\n\
## Follow-ups\n\n{}{raw_section}\n",
        fmt_list(&b.commands, "None captured."),
        fmt_list(&b.findings, "None captured."),
        fmt_task_list(&b.followups, "None captured."),
    )
}

/// Converts captured EventRecords into a plain-text dump for the pipeline.
pub fn events_to_text(events: &[EventRecord], include_urls: bool) -> String {
    let mut lines = Vec::new();
    for ev in events {
        match ev.event_type.as_str() {
            "window" => lines.push(format!("# Window: {}", ev.data)),
            "clipboard" => {
                let text = ev.data.trim();
                if text.contains('\n') {
                    lines.push(format!("# Clipboard:\n{text}"));
                } else {
                    lines.push(text.to_string());
                }
            }
            "browser_url" if include_urls => {
                lines.push(format!("# URL: {}", ev.data));
            }
            "command" => lines.push(format!("$ {}", ev.data)),
            "system" => lines.push(format!("# [{}]", ev.data)),
            _ => {}
        }
    }
    lines.join("\n")
}

/// Sanitise a tool name into a safe path slug.
pub fn tool_slug(name: &str) -> String {
    let re = Regex::new(r"[^\w.\-]").unwrap();
    re.replace_all(name, "-")
        .to_lowercase()
        .trim_matches('-')
        .to_string()
}

// ── Unit tests ─────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── detect_tool ──────────────────────────────────────────────────────────

    #[test]
    fn detect_tool_nmap_scan_report() {
        assert_eq!(detect_tool("Nmap scan report for 10.0.0.1"), Some("nmap"));
    }

    #[test]
    fn detect_tool_nmap_port_table() {
        assert_eq!(detect_tool("PORT   STATE SERVICE\n80/tcp open  http"), Some("nmap"));
    }

    #[test]
    fn detect_tool_metasploit_prompt() {
        assert_eq!(detect_tool("msf6 > use exploit/multi/handler"), Some("metasploit"));
    }

    #[test]
    fn detect_tool_meterpreter() {
        assert_eq!(detect_tool("meterpreter > getuid"), Some("metasploit"));
    }

    #[test]
    fn detect_tool_sqlmap() {
        assert_eq!(detect_tool("sqlmap identified the following injection point"), Some("sqlmap"));
    }

    #[test]
    fn detect_tool_hydra_data_line() {
        assert_eq!(detect_tool("[DATA] attacking ftp://10.0.0.1:21/"), Some("hydra"));
    }

    #[test]
    fn detect_tool_nikto_version() {
        assert_eq!(detect_tool("- Nikto v2.1.6"), Some("nikto"));
    }

    #[test]
    fn detect_tool_hashcat() {
        assert_eq!(detect_tool("hashcat -m 0 -a 0 hash.txt rockyou.txt"), Some("hashcat"));
    }

    #[test]
    fn detect_tool_ffuf() {
        assert_eq!(detect_tool("ffuf -u http://example.com/FUZZ -w wordlist"), Some("ffuf"));
    }

    #[test]
    fn detect_tool_gobuster_dir_mode() {
        assert_eq!(detect_tool("Dir Mode:"), Some("gobuster"));
    }

    #[test]
    fn detect_tool_none_for_unknown() {
        assert_eq!(detect_tool("Hello world, no tools here"), None);
    }

    #[test]
    fn detect_tool_none_for_empty() {
        assert_eq!(detect_tool(""), None);
    }

    #[test]
    fn detect_tool_case_insensitive_nmap() {
        assert_eq!(detect_tool("starting nmap scan"), Some("nmap"));
    }

    #[test]
    fn detect_tool_curl() {
        assert_eq!(detect_tool("curl -s http://example.com/api"), Some("curl"));
    }

    #[test]
    fn detect_tool_wpscan() {
        assert_eq!(detect_tool("wpscan --url http://example.com"), Some("wpscan"));
    }

    // ── redact_text ──────────────────────────────────────────────────────────

    #[test]
    fn redact_password_short_flag() {
        let out = redact_text("hydra -l admin -p s3cr3t ssh://10.0.0.1");
        assert!(!out.contains("s3cr3t"), "password should be redacted");
        assert!(out.contains("[REDACTED]"));
    }

    #[test]
    fn redact_password_long_flag() {
        let out = redact_text("script --password mysupersecret");
        assert!(!out.contains("mysupersecret"));
        assert!(out.contains("[REDACTED]"));
    }

    #[test]
    fn redact_password_equals() {
        let out = redact_text("password=hunter2");
        assert!(!out.contains("hunter2"));
        assert!(out.contains("[REDACTED]"));
    }

    #[test]
    fn redact_api_key() {
        let out = redact_text("api_key=abc123xyz");
        assert!(!out.contains("abc123xyz"));
        assert!(out.contains("[REDACTED]"));
    }

    #[test]
    fn redact_token() {
        let out = redact_text("token=secrettoken");
        assert!(!out.contains("secrettoken"));
        assert!(out.contains("[REDACTED]"));
    }

    #[test]
    fn redact_aws_akia_key() {
        let out = redact_text("Key: AKIAIOSFODNN7EXAMPLE");
        assert!(!out.contains("AKIAIOSFODNN7EXAMPLE"));
        assert!(out.contains("[AWS_KEY_REDACTED]"));
    }

    #[test]
    fn redact_aws_asia_key() {
        let out = redact_text("Key: ASIAIOSFODNN7EXAMPLE");
        assert!(!out.contains("ASIAIOSFODNN7EXAMPLE"));
        assert!(out.contains("[AWS_KEY_REDACTED]"));
    }

    #[test]
    fn redact_jwt() {
        // JWT embedded in a context that does not trigger the token= pattern
        let jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
        let input = format!("Payload: {jwt}");
        let out = redact_text(&input);
        assert!(!out.contains("eyJhbGciOiJIUzI1NiJ9"));
        assert!(out.contains("[JWT_REDACTED]"));
    }

    #[test]
    fn redact_no_false_positive_on_plain_text() {
        let plain = "nmap scan results for 10.0.0.1";
        assert_eq!(redact_text(plain), plain);
    }

    // ── normalize_lines ──────────────────────────────────────────────────────

    #[test]
    fn normalize_deduplicates_exact_lines() {
        let lines: Vec<String> = vec![
            "nmap -sV target".into(),
            "nmap -sV target".into(),
            "other".into(),
        ];
        let result = normalize_lines(&lines);
        assert_eq!(result.iter().filter(|l| l.as_str() == "nmap -sV target").count(), 1);
    }

    #[test]
    fn normalize_collapses_consecutive_blank_lines() {
        let lines: Vec<String> = vec!["a".into(), "".into(), "".into(), "b".into()];
        let result = normalize_lines(&lines);
        let blank_count = result.iter().filter(|l| l.trim().is_empty()).count();
        assert_eq!(blank_count, 1);
    }

    #[test]
    fn normalize_preserves_single_blank() {
        let lines: Vec<String> = vec!["a".into(), "".into(), "b".into()];
        let result = normalize_lines(&lines);
        assert_eq!(result, vec!["a", "", "b"]);
    }

    #[test]
    fn normalize_strips_trailing_whitespace() {
        let lines: Vec<String> = vec!["hello   ".into()];
        let result = normalize_lines(&lines);
        assert_eq!(result, vec!["hello"]);
    }

    #[test]
    fn normalize_empty_input() {
        let result = normalize_lines(&[]);
        assert!(result.is_empty());
    }

    #[test]
    fn normalize_preserves_order() {
        let lines: Vec<String> = vec!["first".into(), "second".into(), "third".into()];
        let result = normalize_lines(&lines);
        assert_eq!(result, vec!["first", "second", "third"]);
    }

    // ── classify_lines ───────────────────────────────────────────────────────

    #[test]
    fn classify_shell_prompt_as_command() {
        let lines: Vec<String> = vec!["$ nmap -sV 10.0.0.1".into()];
        let b = classify_lines(&lines, false);
        assert!(b.commands.iter().any(|c| c.contains("nmap")));
        assert!(b.findings.is_empty());
        assert!(b.followups.is_empty());
    }

    #[test]
    fn classify_tool_name_as_command() {
        let lines: Vec<String> = vec!["nmap -sV target".into()];
        let b = classify_lines(&lines, false);
        assert!(!b.commands.is_empty());
    }

    #[test]
    fn classify_nmap_port_as_finding() {
        let lines: Vec<String> = vec!["80/tcp open  http".into()];
        let b = classify_lines(&lines, false);
        assert!(!b.findings.is_empty());
    }

    #[test]
    fn classify_cve_as_finding() {
        let lines: Vec<String> = vec!["CVE-2021-44228 vulnerability found".into()];
        let b = classify_lines(&lines, false);
        assert!(!b.findings.is_empty());
    }

    #[test]
    fn classify_todo_as_followup() {
        let lines: Vec<String> = vec!["TODO: check for LFI".into()];
        let b = classify_lines(&lines, false);
        assert!(!b.followups.is_empty());
    }

    #[test]
    fn classify_question_as_followup() {
        let lines: Vec<String> = vec!["Is port 8080 exploitable?".into()];
        let b = classify_lines(&lines, false);
        assert!(!b.followups.is_empty());
    }

    #[test]
    fn classify_blank_lines_skipped() {
        let lines: Vec<String> = vec!["".into(), "   ".into()];
        let b = classify_lines(&lines, false);
        assert!(b.commands.is_empty() && b.findings.is_empty()
            && b.followups.is_empty() && b.raw.is_empty());
    }

    #[test]
    fn classify_unrecognised_goes_to_raw() {
        let lines: Vec<String> = vec!["just some random text here".into()];
        let b = classify_lines(&lines, false);
        assert_eq!(b.raw, vec!["just some random text here"]);
    }

    #[test]
    fn classify_redact_flag_applied() {
        let lines: Vec<String> = vec!["$ hydra -p s3cr3t target".into()];
        let b = classify_lines(&lines, true);
        for cmd in &b.commands {
            assert!(!cmd.contains("s3cr3t"), "password should be redacted");
        }
    }

    #[test]
    fn classify_http_200_as_finding() {
        let lines: Vec<String> = vec!["HTTP/1.1 200 OK".into()];
        let b = classify_lines(&lines, false);
        assert!(!b.findings.is_empty());
    }

    // ── build_note ───────────────────────────────────────────────────────────

    fn empty_buckets() -> Buckets {
        Buckets::default()
    }

    #[test]
    fn build_note_contains_yaml_frontmatter() {
        let b = empty_buckets();
        let note = build_note("nmap", "2026-04-17", &b);
        assert!(note.contains("---"));
        assert!(note.contains("tool: nmap"));
        assert!(note.contains("date: 2026-04-17"));
    }

    #[test]
    fn build_note_contains_required_sections() {
        let b = empty_buckets();
        let note = build_note("nmap", "2026-04-17", &b);
        assert!(note.contains("## Summary"));
        assert!(note.contains("## Commands / Steps"));
        assert!(note.contains("## Findings"));
        assert!(note.contains("## Follow-ups"));
    }

    #[test]
    fn build_note_empty_summary_fallback() {
        let b = empty_buckets();
        let note = build_note("nmap", "2026-04-17", &b);
        assert!(note.contains("No structured content detected"));
    }

    #[test]
    fn build_note_raw_section_included_when_present() {
        let mut b = empty_buckets();
        b.raw.push("Some raw note".into());
        let note = build_note("nmap", "2026-04-17", &b);
        assert!(note.contains("## Raw Notes"));
        assert!(note.contains("Some raw note"));
    }

    #[test]
    fn build_note_raw_section_absent_when_empty() {
        let b = empty_buckets();
        let note = build_note("nmap", "2026-04-17", &b);
        assert!(!note.contains("## Raw Notes"));
    }

    #[test]
    fn build_note_tags_contain_tool() {
        let b = empty_buckets();
        let note = build_note("sqlmap", "2026-04-17", &b);
        assert!(note.contains("tool/sqlmap"));
    }

    #[test]
    fn build_note_commands_listed() {
        let mut b = empty_buckets();
        b.commands.push("nmap -sV target".into());
        b.commands.push("curl http://example.com".into());
        let note = build_note("nmap", "2026-04-17", &b);
        assert!(note.contains("nmap -sV target"));
        assert!(note.contains("curl http://example.com"));
    }

    #[test]
    fn build_note_summary_counts_are_accurate() {
        let mut b = empty_buckets();
        b.commands.push("cmd1".into());
        b.commands.push("cmd2".into());
        b.findings.push("finding1".into());
        let note = build_note("nmap", "2026-04-17", &b);
        assert!(note.contains("2 command(s)"));
        assert!(note.contains("1 finding(s)"));
    }

    // ── events_to_text ───────────────────────────────────────────────────────

    fn make_event(event_type: &str, data: &str) -> EventRecord {
        use crate::event::EventRecord;
        EventRecord::new(event_type, "test", data)
    }

    #[test]
    fn events_to_text_window_event() {
        let events = vec![make_event("window", "Firefox")];
        let text = events_to_text(&events, false);
        assert!(text.contains("# Window: Firefox"));
    }

    #[test]
    fn events_to_text_command_event() {
        let events = vec![make_event("command", "nmap -sV target")];
        let text = events_to_text(&events, false);
        assert!(text.contains("$ nmap -sV target"));
    }

    #[test]
    fn events_to_text_clipboard_single_line() {
        let events = vec![make_event("clipboard", "10.0.0.1")];
        let text = events_to_text(&events, false);
        assert!(text.contains("10.0.0.1"));
        assert!(!text.contains("# Clipboard:"));
    }

    #[test]
    fn events_to_text_clipboard_multiline() {
        let events = vec![make_event("clipboard", "line1\nline2")];
        let text = events_to_text(&events, false);
        assert!(text.contains("# Clipboard:"));
    }

    #[test]
    fn events_to_text_browser_url_excluded_by_default() {
        let events = vec![make_event("browser_url", "https://example.com")];
        let text = events_to_text(&events, false);
        assert!(!text.contains("https://example.com"));
    }

    #[test]
    fn events_to_text_browser_url_included_when_flag_set() {
        let events = vec![make_event("browser_url", "https://example.com")];
        let text = events_to_text(&events, true);
        assert!(text.contains("# URL: https://example.com"));
    }

    #[test]
    fn events_to_text_system_event() {
        let events = vec![make_event("system", "Recording started")];
        let text = events_to_text(&events, false);
        assert!(text.contains("# [Recording started]"));
    }

    #[test]
    fn events_to_text_unknown_type_ignored() {
        let events = vec![make_event("unknown_type", "data")];
        let text = events_to_text(&events, false);
        assert!(text.is_empty());
    }

    #[test]
    fn events_to_text_multiple_events_joined_by_newline() {
        let events = vec![
            make_event("command", "cmd1"),
            make_event("command", "cmd2"),
        ];
        let text = events_to_text(&events, false);
        assert!(text.contains("$ cmd1"));
        assert!(text.contains("$ cmd2"));
        assert!(text.contains('\n'));
    }

    // ── tool_slug ────────────────────────────────────────────────────────────

    #[test]
    fn tool_slug_lowercases() {
        assert_eq!(tool_slug("NMAP"), "nmap");
    }

    #[test]
    fn tool_slug_replaces_spaces_with_dash() {
        assert_eq!(tool_slug("my tool"), "my-tool");
    }

    #[test]
    fn tool_slug_preserves_hyphen() {
        assert_eq!(tool_slug("aircrack-ng"), "aircrack-ng");
    }

    #[test]
    fn tool_slug_preserves_dot() {
        assert_eq!(tool_slug("tool.name"), "tool.name");
    }

    #[test]
    fn tool_slug_strips_leading_trailing_dashes() {
        assert_eq!(tool_slug(" nmap "), "nmap");
    }

    #[test]
    fn tool_slug_replaces_special_chars() {
        assert_eq!(tool_slug("tool/name@1"), "tool-name-1");
    }
}
