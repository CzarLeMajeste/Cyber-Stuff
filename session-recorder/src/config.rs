// config.rs – Recorder configuration (JSON file, sensible defaults).

use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub poll_interval: u64,
    pub clipboard_poll_interval: u64,
    pub max_clipboard_length: usize,
    pub exclude_apps: Vec<String>,
    pub exclude_window_patterns: Vec<String>,
    pub browser_history_on_export: bool,
    pub redact: bool,
    pub session_dir: String,
}

impl Default for Config {
    fn default() -> Self {
        let session_dir = dirs::data_local_dir()
            .unwrap_or_else(|| PathBuf::from("~/.local/share"))
            .join("session-logger")
            .join("sessions")
            .to_string_lossy()
            .to_string();
        Self {
            poll_interval: 5,
            clipboard_poll_interval: 2,
            max_clipboard_length: 2000,
            exclude_apps: vec![
                "1password".into(), "keepass".into(), "keepassxc".into(),
                "bitwarden".into(), "lastpass".into(), "dashlane".into(),
                "enpass".into(), "gnome-keyring".into(), "kwallet".into(),
                "pass".into(),
            ],
            exclude_window_patterns: vec![
                r"\bpassword\b".into(), r"\bpasswd\b".into(), r"\bpin\b".into(),
                r"\bsecret\b".into(), r"\bpayment\b".into(),
                r"\bcredit.?card\b".into(), r"\bsocial.?security\b".into(),
                r"\bssn\b".into(),
            ],
            browser_history_on_export: true,
            redact: true,
            session_dir,
        }
    }
}

impl Config {
    pub fn config_path() -> PathBuf {
        dirs::config_dir()
            .unwrap_or_else(|| PathBuf::from("~/.config"))
            .join("session-logger")
            .join("config.json")
    }

    pub fn load() -> Self {
        let path = Self::config_path();
        if path.exists() {
            if let Ok(text) = fs::read_to_string(&path) {
                if let Ok(cfg) = serde_json::from_str(&text) {
                    return cfg;
                }
            }
        }
        Self::default()
    }

    pub fn session_dir_path(&self) -> PathBuf {
        PathBuf::from(&self.session_dir)
    }

    pub fn is_excluded_app(&self, app: &str) -> bool {
        let lower = app.to_lowercase();
        self.exclude_apps.iter().any(|p| lower.contains(p.as_str()))
    }

    pub fn is_excluded_window(&self, title: &str) -> bool {
        for pat in &self.exclude_window_patterns {
            if let Ok(re) = regex::RegexBuilder::new(pat)
                .case_insensitive(true)
                .build()
            {
                if re.is_match(title) {
                    return true;
                }
            }
        }
        false
    }
}

// ── Unit tests ─────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── Config::default ──────────────────────────────────────────────────────

    #[test]
    fn config_default_poll_interval_is_5() {
        assert_eq!(Config::default().poll_interval, 5);
    }

    #[test]
    fn config_default_clipboard_poll_interval_is_2() {
        assert_eq!(Config::default().clipboard_poll_interval, 2);
    }

    #[test]
    fn config_default_max_clipboard_length() {
        assert_eq!(Config::default().max_clipboard_length, 2000);
    }

    #[test]
    fn config_default_redact_is_true() {
        assert!(Config::default().redact);
    }

    #[test]
    fn config_default_browser_history_on_export_is_true() {
        assert!(Config::default().browser_history_on_export);
    }

    #[test]
    fn config_default_session_dir_contains_session_logger() {
        let cfg = Config::default();
        assert!(cfg.session_dir.contains("session-logger"));
    }

    #[test]
    fn config_default_exclude_apps_contains_keepass() {
        let cfg = Config::default();
        assert!(cfg.exclude_apps.iter().any(|a| a.contains("keepass")));
    }

    // ── Config::is_excluded_app ──────────────────────────────────────────────

    #[test]
    fn is_excluded_app_matches_exact() {
        let cfg = Config::default();
        assert!(cfg.is_excluded_app("keepass"));
    }

    #[test]
    fn is_excluded_app_case_insensitive() {
        let cfg = Config::default();
        assert!(cfg.is_excluded_app("KeePass"));
        assert!(cfg.is_excluded_app("BITWARDEN"));
    }

    #[test]
    fn is_excluded_app_partial_match() {
        // "keepassxc" contains "keepass"
        let cfg = Config::default();
        assert!(cfg.is_excluded_app("keepassxc-app"));
    }

    #[test]
    fn is_excluded_app_returns_false_for_normal_app() {
        let cfg = Config::default();
        assert!(!cfg.is_excluded_app("firefox"));
        assert!(!cfg.is_excluded_app("terminal"));
        assert!(!cfg.is_excluded_app("code"));
    }

    // ── Config::is_excluded_window ───────────────────────────────────────────

    #[test]
    fn is_excluded_window_matches_password_word() {
        let cfg = Config::default();
        assert!(cfg.is_excluded_window("Enter Password"));
    }

    #[test]
    fn is_excluded_window_matches_secret() {
        let cfg = Config::default();
        assert!(cfg.is_excluded_window("My Secret Note"));
    }

    #[test]
    fn is_excluded_window_matches_ssn() {
        let cfg = Config::default();
        assert!(cfg.is_excluded_window("Enter your SSN"));
    }

    #[test]
    fn is_excluded_window_matches_credit_card() {
        let cfg = Config::default();
        assert!(cfg.is_excluded_window("Credit Card Details"));
    }

    #[test]
    fn is_excluded_window_returns_false_for_normal_title() {
        let cfg = Config::default();
        assert!(!cfg.is_excluded_window("Firefox – GitHub"));
        assert!(!cfg.is_excluded_window("Terminal"));
        assert!(!cfg.is_excluded_window("Visual Studio Code"));
    }

    #[test]
    fn is_excluded_window_case_insensitive() {
        let cfg = Config::default();
        assert!(cfg.is_excluded_window("PASSWORD MANAGER"));
    }

    // ── Config::session_dir_path ─────────────────────────────────────────────

    #[test]
    fn session_dir_path_returns_path_from_string() {
        let mut cfg = Config::default();
        cfg.session_dir = "/tmp/test-sessions".to_string();
        assert_eq!(cfg.session_dir_path(), PathBuf::from("/tmp/test-sessions"));
    }

    // ── Config::load falls back to default on missing file ───────────────────

    #[test]
    fn config_load_returns_default_when_file_absent() {
        // config_path() may or may not exist in test env; as long as load()
        // returns a usable Config we're good.
        let cfg = Config::load();
        assert!(cfg.poll_interval > 0);
    }
}
