use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;

use crate::scanner::Device;

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct DeviceRecord {
    pub mac: String,
    pub ips_seen: Vec<String>,
    pub hostnames: Vec<String>,
    pub vendor: String,
    pub custom_name: Option<String>,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
    pub status: String, // "unknown", "known", "flagged"
}

pub type Db = HashMap<String, DeviceRecord>;

fn db_path() -> PathBuf {
    // When run with sudo, resolve the real user's home directory
    let home = if let Ok(sudo_user) = std::env::var("SUDO_USER") {
        format!("/home/{}", sudo_user)
    } else {
        std::env::var("HOME").unwrap_or_else(|_| ".".to_string())
    };
    PathBuf::from(home)
        .join(".config")
        .join("netwatch")
        .join("devices.json")
}

pub fn load_db() -> Result<Db, String> {
    let path = db_path();
    if !path.exists() {
        return Ok(HashMap::new());
    }
    let data = fs::read_to_string(&path).map_err(|e| format!("Failed to read DB: {e}"))?;
    serde_json::from_str(&data).map_err(|e| format!("Failed to parse DB: {e}"))
}

pub fn save_db(db: &Db) -> Result<(), String> {
    let path = db_path();
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|e| format!("Failed to create config dir: {e}"))?;
    }
    let data =
        serde_json::to_string_pretty(db).map_err(|e| format!("Failed to serialize DB: {e}"))?;
    fs::write(&path, data).map_err(|e| format!("Failed to write DB: {e}"))?;

    // If running under sudo, chown the DB file and dir back to the real user
    if let Ok(sudo_user) = std::env::var("SUDO_USER") {
        let _ = std::process::Command::new("chown")
            .args(["-R", &format!("{}:{}", sudo_user, sudo_user)])
            .arg(path.parent().unwrap())
            .output();
    }
    Ok(())
}

pub fn update_device(db: &mut Db, device: &Device) {
    if device.mac.is_empty() {
        return; // Can't track devices without a MAC (e.g. the local host itself)
    }
    let now = Utc::now();
    let mac = device.mac.clone();
    let entry = db.entry(mac.clone()).or_insert_with(|| DeviceRecord {
        mac: mac.clone(),
        ips_seen: Vec::new(),
        hostnames: Vec::new(),
        vendor: device.vendor.clone(),
        custom_name: None,
        first_seen: now,
        last_seen: now,
        status: "unknown".to_string(),
    });
    entry.last_seen = now;
    if !device.vendor.is_empty() {
        entry.vendor = device.vendor.clone();
    }
    if !device.ip.is_empty() && !entry.ips_seen.contains(&device.ip) {
        entry.ips_seen.push(device.ip.clone());
    }
    if !device.hostname.is_empty() && !entry.hostnames.contains(&device.hostname) {
        entry.hostnames.push(device.hostname.clone());
    }
}

/// Set a custom name for a device. Returns false if MAC not found.
pub fn set_name(db: &mut Db, mac: &str, name: &str) -> bool {
    match db.get_mut(mac) {
        Some(record) => {
            record.custom_name = Some(name.to_string());
            record.status = "known".to_string();
            true
        }
        None => false,
    }
}

/// Remove a device from the DB. Returns false if MAC not found.
pub fn remove_device(db: &mut Db, mac: &str) -> bool {
    db.remove(mac).is_some()
}

/// Set device status to "flagged". Returns false if MAC not found.
pub fn set_flag(db: &mut Db, mac: &str) -> bool {
    match db.get_mut(mac) {
        Some(record) => {
            record.status = "flagged".to_string();
            true
        }
        None => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scanner::Device;

    fn make_device(mac: &str, ip: &str, vendor: &str) -> Device {
        Device {
            ip: ip.to_string(),
            mac: mac.to_string(),
            hostname: String::new(),
            vendor: vendor.to_string(),
        }
    }

    #[test]
    fn update_device_new_entry() {
        let mut db: Db = HashMap::new();
        let d = make_device("AA:BB:CC:DD:EE:FF", "192.168.1.5", "Acme");
        update_device(&mut db, &d);
        assert!(db.contains_key("AA:BB:CC:DD:EE:FF"));
        let r = &db["AA:BB:CC:DD:EE:FF"];
        assert_eq!(r.mac, "AA:BB:CC:DD:EE:FF");
        assert_eq!(r.ips_seen, vec!["192.168.1.5"]);
        assert_eq!(r.vendor, "Acme");
        assert_eq!(r.status, "unknown");
    }

    #[test]
    fn update_device_accumulates_ips() {
        let mut db: Db = HashMap::new();
        update_device(
            &mut db,
            &make_device("AA:BB:CC:DD:EE:FF", "10.0.0.1", "Acme"),
        );
        update_device(
            &mut db,
            &make_device("AA:BB:CC:DD:EE:FF", "10.0.0.2", "Acme"),
        );
        let r = &db["AA:BB:CC:DD:EE:FF"];
        assert_eq!(r.ips_seen, vec!["10.0.0.1", "10.0.0.2"]);
    }

    #[test]
    fn update_device_no_duplicate_ips() {
        let mut db: Db = HashMap::new();
        update_device(
            &mut db,
            &make_device("AA:BB:CC:DD:EE:FF", "10.0.0.1", "Acme"),
        );
        update_device(
            &mut db,
            &make_device("AA:BB:CC:DD:EE:FF", "10.0.0.1", "Acme"),
        );
        let r = &db["AA:BB:CC:DD:EE:FF"];
        assert_eq!(r.ips_seen.len(), 1);
    }

    #[test]
    fn update_device_skips_empty_mac() {
        let mut db: Db = HashMap::new();
        update_device(&mut db, &make_device("", "10.0.0.1", ""));
        assert!(db.is_empty());
    }

    #[test]
    fn set_name_known_device() {
        let mut db: Db = HashMap::new();
        update_device(
            &mut db,
            &make_device("AA:BB:CC:DD:EE:FF", "10.0.0.1", "Acme"),
        );
        let ok = set_name(&mut db, "AA:BB:CC:DD:EE:FF", "My Device");
        assert!(ok);
        let r = &db["AA:BB:CC:DD:EE:FF"];
        assert_eq!(r.custom_name.as_deref(), Some("My Device"));
        assert_eq!(r.status, "known");
    }

    #[test]
    fn set_name_unknown_mac_returns_false() {
        let mut db: Db = HashMap::new();
        assert!(!set_name(&mut db, "00:00:00:00:00:00", "Ghost"));
    }

    #[test]
    fn remove_device_known_mac() {
        let mut db: Db = HashMap::new();
        update_device(
            &mut db,
            &make_device("AA:BB:CC:DD:EE:FF", "10.0.0.1", "Acme"),
        );
        let ok = remove_device(&mut db, "AA:BB:CC:DD:EE:FF");
        assert!(ok);
        assert!(db.is_empty());
    }

    #[test]
    fn remove_device_unknown_mac_returns_false() {
        let mut db: Db = HashMap::new();
        assert!(!remove_device(&mut db, "00:00:00:00:00:00"));
    }

    #[test]
    fn set_flag_marks_device() {
        let mut db: Db = HashMap::new();
        update_device(
            &mut db,
            &make_device("AA:BB:CC:DD:EE:FF", "10.0.0.1", "Acme"),
        );
        let ok = set_flag(&mut db, "AA:BB:CC:DD:EE:FF");
        assert!(ok);
        assert_eq!(db["AA:BB:CC:DD:EE:FF"].status, "flagged");
    }
}
