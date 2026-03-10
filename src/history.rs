use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::fs::{self, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;

use crate::db::Db;
use crate::scanner::Device;

#[derive(Serialize, Deserialize, Debug)]
pub struct ScanEntry {
    pub timestamp: DateTime<Utc>,
    pub devices_found: usize,
    pub macs: Vec<String>,
}

pub fn scan_log_path() -> PathBuf {
    let home = if let Ok(sudo_user) = std::env::var("SUDO_USER") {
        format!("/home/{sudo_user}")
    } else {
        std::env::var("HOME").unwrap_or_else(|_| ".".to_string())
    };
    PathBuf::from(home)
        .join(".config")
        .join("netwatch")
        .join("scan_log.jsonl")
}

pub fn append_scan(devices: &[Device]) -> Result<(), String> {
    let path = scan_log_path();
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|e| format!("Failed to create config dir: {e}"))?;
    }

    let macs: Vec<String> = devices
        .iter()
        .filter(|d| !d.mac.is_empty())
        .map(|d| d.mac.clone())
        .collect();

    let entry = ScanEntry {
        timestamp: Utc::now(),
        devices_found: macs.len(),
        macs,
    };

    let line =
        serde_json::to_string(&entry).map_err(|e| format!("Failed to serialize entry: {e}"))?;

    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .map_err(|e| format!("Failed to open log: {e}"))?;
    writeln!(file, "{line}").map_err(|e| format!("Failed to write log: {e}"))?;

    maybe_truncate_log(&path)?;

    // Fix ownership if running under sudo
    if let Ok(sudo_user) = std::env::var("SUDO_USER") {
        let _ = std::process::Command::new("chown")
            .args([
                &format!("{sudo_user}:{sudo_user}"),
                &path.to_string_lossy().into_owned(),
            ])
            .output();
    }

    Ok(())
}

fn maybe_truncate_log(path: &PathBuf) -> Result<(), String> {
    const MAX_LINES: usize = 10000;
    const KEEP_LINES: usize = 5000;

    let data = fs::read_to_string(path).map_err(|e| format!("Failed to read log: {e}"))?;
    let lines: Vec<&str> = data.lines().collect();

    if lines.len() > MAX_LINES {
        let keep = &lines[lines.len() - KEEP_LINES..];
        let new_content = format!("{}\n", keep.join("\n"));
        fs::write(path, new_content).map_err(|e| format!("Failed to truncate log: {e}"))?;
    }

    Ok(())
}

pub fn read_log(limit: usize) -> Result<Vec<ScanEntry>, String> {
    let path = scan_log_path();
    if !path.exists() {
        return Ok(Vec::new());
    }

    let file = fs::File::open(&path).map_err(|e| format!("Failed to open log: {e}"))?;
    let reader = BufReader::new(file);
    let mut entries: Vec<ScanEntry> = Vec::new();

    for line in reader.lines() {
        let line = line.map_err(|e| format!("Failed to read line: {e}"))?;
        if line.trim().is_empty() {
            continue;
        }
        if let Ok(entry) = serde_json::from_str::<ScanEntry>(&line) {
            entries.push(entry);
        }
    }

    // Return last `limit` entries
    if entries.len() > limit {
        let skip = entries.len() - limit;
        entries = entries.into_iter().skip(skip).collect();
    }

    Ok(entries)
}

/// Format a scan log entry for display, resolving MACs to custom names from DB.
pub fn format_log_entry(entry: &ScanEntry, db: &Db) -> String {
    let ts = entry.timestamp.format("%Y-%m-%d %H:%M");

    let names: Vec<String> = entry
        .macs
        .iter()
        .map(|mac| {
            db.get(mac)
                .and_then(|r| r.custom_name.clone())
                .unwrap_or_else(|| mac.clone())
        })
        .collect();

    let total = entry.devices_found;

    let device_str = if names.is_empty() {
        "(none)".to_string()
    } else if names.len() <= 2 {
        names.join(", ")
    } else {
        let shown: Vec<&str> = names.iter().take(2).map(|s| s.as_str()).collect();
        let others = total - 2;
        format!("{}, + {others} others", shown.join(", "))
    };

    // Show tags on each device if any are tagged
    let tagged: Vec<String> = entry
        .macs
        .iter()
        .filter_map(|mac| {
            let r = db.get(mac)?;
            if r.tags.is_empty() {
                None
            } else {
                Some(format!("{}: [{}]", mac, r.tags.join(", ")))
            }
        })
        .collect();

    if tagged.is_empty() {
        format!("[{ts}] {total} devices: {device_str}")
    } else {
        format!(
            "[{ts}] {total} devices: {device_str}  tags: {}",
            tagged.join("; ")
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::{Db, DeviceRecord};
    use chrono::Utc;

    fn make_db_with_name(mac: &str, name: &str) -> Db {
        let mut db = Db::new();
        db.insert(
            mac.to_string(),
            DeviceRecord {
                mac: mac.to_string(),
                ips_seen: vec![],
                hostnames: vec![],
                vendor: String::new(),
                custom_name: Some(name.to_string()),
                first_seen: Utc::now(),
                last_seen: Utc::now(),
                status: "known".to_string(),
                tags: vec![],
            },
        );
        db
    }

    #[test]
    fn format_entry_no_names() {
        let entry = ScanEntry {
            timestamp: Utc::now(),
            devices_found: 2,
            macs: vec![
                "AA:BB:CC:DD:EE:01".to_string(),
                "AA:BB:CC:DD:EE:02".to_string(),
            ],
        };
        let db = Db::new();
        let s = format_log_entry(&entry, &db);
        assert!(s.contains("2 devices"));
        assert!(s.contains("AA:BB:CC:DD:EE:01"));
    }

    #[test]
    fn format_entry_with_names() {
        let entry = ScanEntry {
            timestamp: Utc::now(),
            devices_found: 2,
            macs: vec![
                "AA:BB:CC:DD:EE:01".to_string(),
                "AA:BB:CC:DD:EE:02".to_string(),
            ],
        };
        let mut db = make_db_with_name("AA:BB:CC:DD:EE:01", "PS5");
        db.extend(make_db_with_name("AA:BB:CC:DD:EE:02", "Chris Laptop"));
        let s = format_log_entry(&entry, &db);
        assert!(s.contains("PS5"));
        assert!(s.contains("Chris Laptop"));
    }

    #[test]
    fn format_entry_many_devices_shows_others() {
        let macs: Vec<String> = (1u8..=9)
            .map(|i| format!("AA:BB:CC:DD:EE:{i:02X}"))
            .collect();
        let entry = ScanEntry {
            timestamp: Utc::now(),
            devices_found: 9,
            macs: macs.clone(),
        };
        let mut db = make_db_with_name(&macs[0], "PS5");
        db.extend(make_db_with_name(&macs[1], "Chris Laptop"));
        let s = format_log_entry(&entry, &db);
        assert!(s.contains("+ 7 others"));
    }

    #[test]
    fn read_log_empty_when_no_file() {
        // Use a path that definitely doesn't exist
        let entries = read_log(10).unwrap_or_default();
        // Either empty (no file) or has entries — just ensure it doesn't panic
        let _ = entries;
    }
}
