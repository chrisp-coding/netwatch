use colored::Colorize;
use serde::{Deserialize, Serialize};
use std::process::Command;

use crate::db::{Db, DeviceRecord};
use crate::oui;

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
        .map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                "nmap not found. Install it with: sudo apt install nmap".to_string()
            } else {
                format!("Failed to run nmap: {e}")
            }
        })?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        if stderr.contains("Operation not permitted") || stderr.contains("requires root") {
            return Err("nmap requires root privileges. Run netwatch with sudo.".to_string());
        }
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
        if let Some(rest) = line.strip_prefix("Nmap scan report for ") {
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

            if let Some(paren) = rest.find('(') {
                current_hostname = rest[..paren].trim().to_string();
                current_ip = rest[paren + 1..].trim_end_matches(')').to_string();
            } else {
                current_ip = rest.to_string();
                current_hostname = String::new();
            }
        } else if let Some(rest) = line.strip_prefix("MAC Address: ") {
            if let Some(paren) = rest.find('(') {
                current_mac = rest[..paren].trim().to_string();
                let reported = rest[paren + 1..].trim_end_matches(')').to_string();
                // Use OUI lookup when nmap doesn't know the vendor
                if reported.is_empty() || reported.eq_ignore_ascii_case("unknown") {
                    current_vendor = oui::lookup(&current_mac)
                        .map(|s| s.to_string())
                        .unwrap_or_default();
                } else {
                    current_vendor = reported;
                }
            } else {
                current_mac = rest.trim().to_string();
                current_vendor = oui::lookup(&current_mac)
                    .map(|s| s.to_string())
                    .unwrap_or_default();
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

/// Returns true if the MAC address uses a locally-administered (random/private) address.
/// Bit 1 of the first octet (the "locally administered" bit, 0x02) indicates this.
pub fn is_random_mac(mac: &str) -> bool {
    let first = mac.split(':').next().unwrap_or("");
    u8::from_str_radix(first, 16)
        .map(|b| b & 0x02 != 0)
        .unwrap_or(false)
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

    let col_name = rows
        .iter()
        .map(|(_, n, _)| n.len())
        .max()
        .unwrap_or(0)
        .max(4);
    let col_ip = devices
        .iter()
        .map(|d| d.ip.len())
        .max()
        .unwrap_or(0)
        .max(15);
    let col_mac = devices
        .iter()
        .map(|d| d.mac.len())
        .max()
        .unwrap_or(0)
        .max(17);
    let col_host = devices
        .iter()
        .map(|d| d.hostname.len())
        .max()
        .unwrap_or(0)
        .max(8);
    let col_vendor = devices
        .iter()
        .map(|d| {
            let base = d.vendor.len();
            if !d.mac.is_empty() && is_random_mac(&d.mac) {
                base + " (random)".len()
            } else {
                base
            }
        })
        .max()
        .unwrap_or(0)
        .max(6);
    let col_status = rows
        .iter()
        .map(|(_, _, s)| s.len())
        .max()
        .unwrap_or(0)
        .max(7);

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
        let padded_status = format!("{:<col_status$}", status);
        let colored_status = colorize_status(status.trim());
        let status_display = format!("{}{}", colored_status, &padded_status[status.len()..]);

        let vendor_plain = if !d.mac.is_empty() && is_random_mac(&d.mac) {
            format!("{} (random)", d.vendor)
        } else {
            d.vendor.clone()
        };
        let padded_vendor = format!("{:<col_vendor$}", vendor_plain);
        let vendor_display = if !d.mac.is_empty() && is_random_mac(&d.mac) {
            format!(
                "{}{}{}",
                d.vendor,
                " (random)".dimmed().italic(),
                &padded_vendor[vendor_plain.len()..]
            )
        } else {
            padded_vendor
        };

        println!(
            "| {:<col_name$} | {:<col_ip$} | {:<col_mac$} | {:<col_host$} | {} | {} |",
            name, d.ip, d.mac, d.hostname, vendor_display, status_display,
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

fn colorize_status(s: &str) -> String {
    match s {
        "known" => "known".green().to_string(),
        "*flagged" | "flagged" => "*flagged".red().bold().to_string(),
        "new" => "new".yellow().bold().to_string(),
        "unknown" => "unknown".yellow().to_string(),
        other => other.to_string(),
    }
}

/// Print all devices from DB. Columns: Name | MAC | Last IP | Hostname | Vendor | First Seen | Last Seen | Status | Tags
pub fn print_list_table(db: &Db, tag_filter: Option<&str>) {
    let mut records: Vec<&DeviceRecord> = db
        .values()
        .filter(|r| {
            if let Some(tag) = tag_filter {
                r.tags.contains(&tag.to_string())
            } else {
                true
            }
        })
        .collect();
    if records.is_empty() {
        if tag_filter.is_some() {
            println!("No devices with that tag.");
        } else {
            println!("No devices in database. Run 'scan' first.");
        }
        return;
    }
    records.sort_by(|a, b| b.last_seen.cmp(&a.last_seen));

    let fmt_time = |dt: &chrono::DateTime<chrono::Utc>| dt.format("%Y-%m-%d %H:%M").to_string();

    let col_name = records
        .iter()
        .map(|r| r.custom_name.as_deref().unwrap_or("").len())
        .max()
        .unwrap_or(0)
        .max(4);
    let col_mac = records
        .iter()
        .map(|r| r.mac.len())
        .max()
        .unwrap_or(0)
        .max(17);
    let col_ip = records
        .iter()
        .map(|r| r.ips_seen.last().map(|s| s.len()).unwrap_or(0))
        .max()
        .unwrap_or(0)
        .max(15);
    let col_host = records
        .iter()
        .map(|r| r.hostnames.last().map(|s| s.len()).unwrap_or(0))
        .max()
        .unwrap_or(0)
        .max(8);
    let col_vendor = records
        .iter()
        .map(|r| r.vendor.len())
        .max()
        .unwrap_or(0)
        .max(6);
    let col_time = 16; // "YYYY-MM-DD HH:MM"
    let col_status = records
        .iter()
        .map(|r| fmt_status(&r.status).len())
        .max()
        .unwrap_or(0)
        .max(7);
    let col_tags = records
        .iter()
        .map(|r| {
            if r.tags.is_empty() {
                0
            } else {
                r.tags.join(", ").len()
            }
        })
        .max()
        .unwrap_or(0)
        .max(4);

    let sep = format!(
        "+-{}-+-{}-+-{}-+-{}-+-{}-+-{}-+-{}-+-{}-+-{}-+",
        "-".repeat(col_name),
        "-".repeat(col_mac),
        "-".repeat(col_ip),
        "-".repeat(col_host),
        "-".repeat(col_vendor),
        "-".repeat(col_time),
        "-".repeat(col_time),
        "-".repeat(col_status),
        "-".repeat(col_tags),
    );

    println!("{sep}");
    println!(
        "| {:<col_name$} | {:<col_mac$} | {:<col_ip$} | {:<col_host$} | {:<col_vendor$} | {:<col_time$} | {:<col_time$} | {:<col_status$} | {:<col_tags$} |",
        "Name", "MAC", "Last IP", "Hostname", "Vendor", "First Seen", "Last Seen", "Status", "Tags",
    );
    println!("{sep}");

    for r in &records {
        let name = r.custom_name.as_deref().unwrap_or("");
        let ip = r.ips_seen.last().map(|s| s.as_str()).unwrap_or("");
        let host = r.hostnames.last().map(|s| s.as_str()).unwrap_or("");
        let status_plain = fmt_status(&r.status);
        let padded_status = format!("{:<col_status$}", status_plain);
        let colored_status = colorize_status(status_plain.trim());
        let status_display = format!("{}{}", colored_status, &padded_status[status_plain.len()..]);
        let tags = r.tags.join(", ");
        println!(
            "| {:<col_name$} | {:<col_mac$} | {:<col_ip$} | {:<col_host$} | {:<col_vendor$} | {:<col_time$} | {:<col_time$} | {} | {:<col_tags$} |",
            name, r.mac, ip, host, r.vendor,
            fmt_time(&r.first_seen), fmt_time(&r.last_seen), status_display, tags,
        );
    }

    println!("{sep}");
    println!("{} device(s) in database.", records.len());
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_nmap_output() -> &'static str {
        "\
Starting Nmap 7.80 ( https://nmap.org ) at 2024-01-01 12:00 UTC
Nmap scan report for router.local (192.168.1.1)
Host is up (0.0010s latency).
MAC Address: AC:1F:6B:11:22:33 (Cisco)
Nmap scan report for 192.168.1.50
Host is up (0.0020s latency).
MAC Address: B8:27:EB:AA:BB:CC (Unknown)
Nmap scan report for myphone.local (192.168.1.100)
Host is up (0.0030s latency).
MAC Address: 00:03:93:DD:EE:FF (Apple)
Nmap scan report for 192.168.1.200
Host is up (0.0040s latency).
Nmap done: 256 IP addresses (4 hosts up) scanned in 2.50 seconds
"
    }

    #[test]
    fn parse_finds_all_devices() {
        let devices = parse_nmap_output(sample_nmap_output());
        assert_eq!(devices.len(), 4);
    }

    #[test]
    fn parse_hostname_with_ip() {
        let devices = parse_nmap_output(sample_nmap_output());
        let router = &devices[0];
        assert_eq!(router.ip, "192.168.1.1");
        assert_eq!(router.hostname, "router.local");
        assert_eq!(router.mac, "AC:1F:6B:11:22:33");
        assert_eq!(router.vendor, "Cisco");
    }

    #[test]
    fn parse_ip_only_no_hostname() {
        let devices = parse_nmap_output(sample_nmap_output());
        // 192.168.1.50 has no hostname
        let d = &devices[1];
        assert_eq!(d.ip, "192.168.1.50");
        assert_eq!(d.hostname, "");
        assert_eq!(d.mac, "B8:27:EB:AA:BB:CC");
        // nmap reports "Unknown", so OUI lookup should give "Raspberry Pi Foundation"
        assert_eq!(d.vendor, "Raspberry Pi Foundation");
    }

    #[test]
    fn parse_known_vendor_preserved() {
        let devices = parse_nmap_output(sample_nmap_output());
        let apple = &devices[2];
        assert_eq!(apple.vendor, "Apple");
    }

    #[test]
    fn parse_no_mac_device() {
        let devices = parse_nmap_output(sample_nmap_output());
        // 192.168.1.200 has no MAC line (local host)
        let d = &devices[3];
        assert_eq!(d.ip, "192.168.1.200");
        assert_eq!(d.mac, "");
        assert_eq!(d.vendor, "");
    }

    #[test]
    fn parse_empty_output() {
        let devices = parse_nmap_output("");
        assert!(devices.is_empty());
    }

    #[test]
    fn parse_no_hosts() {
        let output = "Starting Nmap 7.80\nNmap done: 256 IP addresses (0 hosts up)\n";
        let devices = parse_nmap_output(output);
        assert!(devices.is_empty());
    }

    #[test]
    fn random_mac_locally_administered_bit_set() {
        // 0x02 bit set in first octet → locally administered (random)
        assert!(is_random_mac("02:AA:BB:CC:DD:EE")); // 0x02
        assert!(is_random_mac("06:AA:BB:CC:DD:EE")); // 0x06
        assert!(is_random_mac("0A:AA:BB:CC:DD:EE")); // 0x0A
        assert!(is_random_mac("AA:BB:CC:DD:EE:FF")); // 0xAA = 1010 1010, bit1=1
    }

    #[test]
    fn random_mac_globally_unique_not_random() {
        assert!(!is_random_mac("AC:1F:6B:11:22:33")); // 0xAC = 1010 1100, bit1=0
        assert!(!is_random_mac("B8:27:EB:AA:BB:CC")); // 0xB8 = 1011 1000, bit1=0
        assert!(!is_random_mac("00:03:93:DD:EE:FF")); // 0x00, bit1=0
    }

    #[test]
    fn random_mac_invalid_returns_false() {
        assert!(!is_random_mac(""));
        assert!(!is_random_mac("not:a:mac"));
    }
}
