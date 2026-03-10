use serde::{Deserialize, Serialize};
use std::process::Command;

use crate::db::{Db, DeviceRecord};

#[derive(Serialize, Deserialize, Debug)]
pub struct Device {
    pub ip: String,
    pub mac: String,
    pub hostname: String,
    pub vendor: String,
}

pub fn run_scan(subnet: &str) -> Result<Vec<Device>, String> {
    let output = Command::new("sudo")
        .args(["nmap", "-sn", subnet])
        .output()
        .map_err(|e| format!("Failed to run nmap: {e}"))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!("nmap failed: {stderr}"));
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    Ok(parse_nmap_output(&stdout))
}

fn parse_nmap_output(output: &str) -> Vec<Device> {
    let mut devices = Vec::new();
    let mut current_ip = String::new();
    let mut current_hostname = String::new();
    let mut current_mac = String::new();
    let mut current_vendor = String::new();

    for line in output.lines() {
        let line = line.trim();

        // "Nmap scan report for hostname (1.2.3.4)" or "Nmap scan report for 1.2.3.4"
        if line.starts_with("Nmap scan report for ") {
            if !current_ip.is_empty() {
                devices.push(Device {
                    ip: current_ip.clone(),
                    mac: current_mac.clone(),
                    hostname: current_hostname.clone(),
                    vendor: current_vendor.clone(),
                });
            }
            current_mac.clear();
            current_vendor.clear();

            let rest = &line["Nmap scan report for ".len()..];
            if let Some(paren) = rest.find('(') {
                current_hostname = rest[..paren].trim().to_string();
                current_ip = rest[paren + 1..].trim_end_matches(')').to_string();
            } else {
                current_ip = rest.to_string();
                current_hostname = String::new();
            }
        } else if line.starts_with("MAC Address: ") {
            let rest = &line["MAC Address: ".len()..];
            if let Some(paren) = rest.find('(') {
                current_mac = rest[..paren].trim().to_string();
                current_vendor = rest[paren + 1..].trim_end_matches(')').to_string();
            } else {
                current_mac = rest.trim().to_string();
                current_vendor = String::new();
            }
        }
    }

    if !current_ip.is_empty() {
        devices.push(Device {
            ip: current_ip,
            mac: current_mac,
            hostname: current_hostname,
            vendor: current_vendor,
        });
    }

    devices
}

/// Print scan results. Columns: Name | IP | MAC | Hostname | Vendor | Status
/// Name and Status are pulled from the DB when available.
pub fn print_scan_table(devices: &[Device], db: &Db) {
    if devices.is_empty() {
        println!("No devices found.");
        return;
    }

    // Resolve name/status from DB for each device
    let rows: Vec<(&Device, String, String)> = devices
        .iter()
        .map(|d| {
            let (name, status) = if d.mac.is_empty() {
                (String::new(), String::new())
            } else {
                match db.get(&d.mac) {
                    Some(r) => (
                        r.custom_name.clone().unwrap_or_default(),
                        fmt_status(&r.status),
                    ),
                    None => (String::new(), "new".to_string()),
                }
            };
            (d, name, status)
        })
        .collect();

    let col_name = rows.iter().map(|(_, n, _)| n.len()).max().unwrap_or(0).max(4);
    let col_ip = devices.iter().map(|d| d.ip.len()).max().unwrap_or(0).max(15);
    let col_mac = devices.iter().map(|d| d.mac.len()).max().unwrap_or(0).max(17);
    let col_host = devices.iter().map(|d| d.hostname.len()).max().unwrap_or(0).max(8);
    let col_vendor = devices.iter().map(|d| d.vendor.len()).max().unwrap_or(0).max(6);
    let col_status = rows.iter().map(|(_, _, s)| s.len()).max().unwrap_or(0).max(7);

    let sep = format!(
        "+-{}-+-{}-+-{}-+-{}-+-{}-+-{}-+",
        "-".repeat(col_name),
        "-".repeat(col_ip),
        "-".repeat(col_mac),
        "-".repeat(col_host),
        "-".repeat(col_vendor),
        "-".repeat(col_status),
    );

    println!("{sep}");
    println!(
        "| {:<col_name$} | {:<col_ip$} | {:<col_mac$} | {:<col_host$} | {:<col_vendor$} | {:<col_status$} |",
        "Name", "IP", "MAC", "Hostname", "Vendor", "Status",
    );
    println!("{sep}");

    for (d, name, status) in &rows {
        println!(
            "| {:<col_name$} | {:<col_ip$} | {:<col_mac$} | {:<col_host$} | {:<col_vendor$} | {:<col_status$} |",
            name, d.ip, d.mac, d.hostname, d.vendor, status,
        );
    }

    println!("{sep}");
    println!("{} device(s) found.", devices.len());
}

fn fmt_status(s: &str) -> String {
    if s == "flagged" {
        "*flagged".to_string()
    } else {
        s.to_string()
    }
}

/// Print all devices from DB. Columns: Name | MAC | Last IP | Hostname | Vendor | First Seen | Last Seen | Status
pub fn print_list_table(db: &Db) {
    let mut records: Vec<&DeviceRecord> = db.values().collect();
    if records.is_empty() {
        println!("No devices in database. Run 'scan' first.");
        return;
    }
    records.sort_by(|a, b| b.last_seen.cmp(&a.last_seen));

    let fmt_time = |dt: &chrono::DateTime<chrono::Utc>| {
        dt.format("%Y-%m-%d %H:%M").to_string()
    };

    let col_name = records.iter().map(|r| r.custom_name.as_deref().unwrap_or("").len()).max().unwrap_or(0).max(4);
    let col_mac = records.iter().map(|r| r.mac.len()).max().unwrap_or(0).max(17);
    let col_ip = records.iter().map(|r| r.ips_seen.last().map(|s| s.len()).unwrap_or(0)).max().unwrap_or(0).max(15);
    let col_host = records.iter().map(|r| r.hostnames.last().map(|s| s.len()).unwrap_or(0)).max().unwrap_or(0).max(8);
    let col_vendor = records.iter().map(|r| r.vendor.len()).max().unwrap_or(0).max(6);
    let col_time = 16; // "YYYY-MM-DD HH:MM"
    let col_status = records.iter().map(|r| fmt_status(&r.status).len()).max().unwrap_or(0).max(7);

    let sep = format!(
        "+-{}-+-{}-+-{}-+-{}-+-{}-+-{}-+-{}-+-{}-+",
        "-".repeat(col_name),
        "-".repeat(col_mac),
        "-".repeat(col_ip),
        "-".repeat(col_host),
        "-".repeat(col_vendor),
        "-".repeat(col_time),
        "-".repeat(col_time),
        "-".repeat(col_status),
    );

    println!("{sep}");
    println!(
        "| {:<col_name$} | {:<col_mac$} | {:<col_ip$} | {:<col_host$} | {:<col_vendor$} | {:<col_time$} | {:<col_time$} | {:<col_status$} |",
        "Name", "MAC", "Last IP", "Hostname", "Vendor", "First Seen", "Last Seen", "Status",
    );
    println!("{sep}");

    for r in &records {
        let name = r.custom_name.as_deref().unwrap_or("");
        let ip = r.ips_seen.last().map(|s| s.as_str()).unwrap_or("");
        let host = r.hostnames.last().map(|s| s.as_str()).unwrap_or("");
        println!(
            "| {:<col_name$} | {:<col_mac$} | {:<col_ip$} | {:<col_host$} | {:<col_vendor$} | {:<col_time$} | {:<col_time$} | {:<col_status$} |",
            name, r.mac, ip, host, r.vendor,
            fmt_time(&r.first_seen), fmt_time(&r.last_seen), fmt_status(&r.status),
        );
    }

    println!("{sep}");
    println!("{} device(s) in database.", records.len());
}
