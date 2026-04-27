// event.rs – EventRecord data type and JSONL-backed EventStore.

use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs::{self, OpenOptions};
use std::io::{self, BufRead, Write};
use std::path::PathBuf;
use std::sync::Mutex;

/// A single captured desktop event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventRecord {
    pub ts: String,
    #[serde(rename = "type")]
    pub event_type: String,
    pub source: String,
    pub data: String,
    #[serde(default)]
    pub app: String,
    #[serde(default)]
    pub extra: HashMap<String, serde_json::Value>,
}

impl EventRecord {
    pub fn new(event_type: &str, source: &str, data: &str) -> Self {
        Self {
            ts: Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string(),
            event_type: event_type.to_string(),
            source: source.to_string(),
            data: data.to_string(),
            app: String::new(),
            extra: HashMap::new(),
        }
    }

    pub fn with_app(mut self, app: &str) -> Self {
        self.app = app.to_string();
        self
    }

    /// Returns the YYYY-MM-DD date portion of the timestamp.
    pub fn date_str(&self) -> &str {
        &self.ts[..10]
    }
}

/// Appends EventRecord objects to a per-day JSONL file.
pub struct EventStore {
    dir: PathBuf,
    mutex: Mutex<()>,
}

impl EventStore {
    pub fn new(dir: PathBuf) -> Self {
        Self {
            dir,
            mutex: Mutex::new(()),
        }
    }

    pub(crate) fn path_for(&self, date_str: &str) -> PathBuf {
        let year = &date_str[..4];
        let p = self.dir.join(year).join(format!("{date_str}.jsonl"));
        if let Some(parent) = p.parent() {
            let _ = fs::create_dir_all(parent);
        }
        p
    }

    pub fn write(&self, event: &EventRecord) -> io::Result<()> {
        let _guard = self.mutex.lock().unwrap();
        let path = self.path_for(event.date_str());
        let line = serde_json::to_string(event)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)?;
        writeln!(file, "{line}")
    }

    pub fn read(&self, date_str: &str) -> io::Result<Vec<EventRecord>> {
        let path = self.path_for(date_str);
        if !path.exists() {
            return Ok(vec![]);
        }
        let file = fs::File::open(path)?;
        let reader = io::BufReader::new(file);
        let mut events = Vec::new();
        for line in reader.lines() {
            let line = line?;
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            if let Ok(ev) = serde_json::from_str::<EventRecord>(line) {
                events.push(ev);
            }
        }
        Ok(events)
    }

    /// Lists all dates for which a JSONL log exists.
    pub fn available_dates(&self) -> Vec<String> {
        let mut dates = Vec::new();
        if let Ok(year_dirs) = fs::read_dir(&self.dir) {
            for year_entry in year_dirs.flatten() {
                if let Ok(day_files) = fs::read_dir(year_entry.path()) {
                    for entry in day_files.flatten() {
                        let path = entry.path();
                        if path.extension().and_then(|e| e.to_str()) == Some("jsonl") {
                            if let Some(stem) = path.file_stem().and_then(|s| s.to_str()) {
                                dates.push(stem.to_string());
                            }
                        }
                    }
                }
            }
        }
        dates.sort();
        dates
    }
}

// ── Unit tests ─────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    // ── EventRecord ──────────────────────────────────────────────────────────

    #[test]
    fn event_record_new_fills_fields() {
        let ev = EventRecord::new("command", "shell", "nmap -sV target");
        assert_eq!(ev.event_type, "command");
        assert_eq!(ev.source, "shell");
        assert_eq!(ev.data, "nmap -sV target");
        assert!(ev.app.is_empty());
        assert!(ev.extra.is_empty());
    }

    #[test]
    fn event_record_timestamp_is_iso8601() {
        let ev = EventRecord::new("window", "tracker", "Firefox");
        // Timestamps look like 2026-04-17T10:00:00Z – at least 10 chars
        assert!(ev.ts.len() >= 10);
        assert!(ev.ts.contains('T') || ev.ts.contains('-'));
    }

    #[test]
    fn event_record_with_app_sets_app_field() {
        let ev = EventRecord::new("window", "tracker", "My Window").with_app("firefox");
        assert_eq!(ev.app, "firefox");
    }

    #[test]
    fn event_record_date_str_returns_first_10_chars() {
        let mut ev = EventRecord::new("system", "recorder", "start");
        ev.ts = "2026-04-17T10:00:00Z".to_string();
        assert_eq!(ev.date_str(), "2026-04-17");
    }

    #[test]
    fn event_record_serialises_and_deserialises() {
        let ev = EventRecord::new("command", "shell", "ls -la").with_app("terminal");
        let json = serde_json::to_string(&ev).expect("serialize");
        let decoded: EventRecord = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(decoded.event_type, "command");
        assert_eq!(decoded.data, "ls -la");
        assert_eq!(decoded.app, "terminal");
    }

    // ── EventStore ───────────────────────────────────────────────────────────

    fn make_store() -> (TempDir, EventStore) {
        let dir = TempDir::new().expect("temp dir");
        let store = EventStore::new(dir.path().to_path_buf());
        (dir, store)
    }

    #[test]
    fn event_store_write_and_read_round_trip() {
        let (_dir, store) = make_store();
        let mut ev = EventRecord::new("command", "shell", "nmap -sV 10.0.0.1");
        ev.ts = "2026-04-17T10:00:00Z".to_string();

        store.write(&ev).expect("write");
        let events = store.read("2026-04-17").expect("read");

        assert_eq!(events.len(), 1);
        assert_eq!(events[0].event_type, "command");
        assert_eq!(events[0].data, "nmap -sV 10.0.0.1");
    }

    #[test]
    fn event_store_read_returns_empty_for_missing_date() {
        let (_dir, store) = make_store();
        let events = store.read("2026-01-01").expect("read");
        assert!(events.is_empty());
    }

    #[test]
    fn event_store_multiple_events_same_day() {
        let (_dir, store) = make_store();
        let mut ev1 = EventRecord::new("command", "shell", "cmd1");
        ev1.ts = "2026-04-17T10:00:00Z".to_string();
        let mut ev2 = EventRecord::new("window", "tracker", "Firefox");
        ev2.ts = "2026-04-17T10:01:00Z".to_string();

        store.write(&ev1).expect("write ev1");
        store.write(&ev2).expect("write ev2");

        let events = store.read("2026-04-17").expect("read");
        assert_eq!(events.len(), 2);
    }

    #[test]
    fn event_store_events_on_different_days_are_separate() {
        let (_dir, store) = make_store();
        let mut ev1 = EventRecord::new("command", "shell", "cmd1");
        ev1.ts = "2026-04-17T10:00:00Z".to_string();
        let mut ev2 = EventRecord::new("command", "shell", "cmd2");
        ev2.ts = "2026-04-18T10:00:00Z".to_string();

        store.write(&ev1).expect("write");
        store.write(&ev2).expect("write");

        let day1 = store.read("2026-04-17").expect("read day1");
        let day2 = store.read("2026-04-18").expect("read day2");

        assert_eq!(day1.len(), 1);
        assert_eq!(day2.len(), 1);
        assert_eq!(day1[0].data, "cmd1");
        assert_eq!(day2[0].data, "cmd2");
    }

    #[test]
    fn event_store_available_dates_lists_written_dates() {
        let (_dir, store) = make_store();
        let mut ev = EventRecord::new("command", "shell", "cmd");
        ev.ts = "2026-04-17T10:00:00Z".to_string();
        store.write(&ev).expect("write");

        let dates = store.available_dates();
        assert!(dates.contains(&"2026-04-17".to_string()));
    }

    #[test]
    fn event_store_available_dates_sorted() {
        let (_dir, store) = make_store();
        for date in ["2026-04-19", "2026-04-17", "2026-04-18"] {
            let mut ev = EventRecord::new("command", "shell", "cmd");
            ev.ts = format!("{date}T10:00:00Z");
            store.write(&ev).expect("write");
        }
        let dates = store.available_dates();
        let mut sorted = dates.clone();
        sorted.sort();
        assert_eq!(dates, sorted);
    }

    #[test]
    fn event_store_skips_invalid_json_lines() {
        let (_dir, store) = make_store();
        let mut ev = EventRecord::new("command", "shell", "valid");
        ev.ts = "2026-04-17T10:00:00Z".to_string();
        store.write(&ev).expect("write valid");

        // Manually inject a bad line into the JSONL file
        let jsonl_path = store.path_for("2026-04-17");
        let existing = fs::read_to_string(&jsonl_path).unwrap_or_default();
        fs::write(&jsonl_path, format!("{existing}not-json\n")).expect("inject bad line");

        let events = store.read("2026-04-17").expect("read");
        // The valid event should still be there
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].data, "valid");
    }
}
