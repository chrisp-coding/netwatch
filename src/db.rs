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
        fs::create_dir_all(parent)
            .map_err(|e| format!("Failed to create config dir: {e}"))?;
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
