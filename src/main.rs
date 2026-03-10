mod db;
mod oui;
mod scanner;

use clap::{Parser, Subcommand};
use colored::Colorize;
use std::collections::HashSet;
use std::process::Command;

#[derive(Parser)]
#[command(name = "netwatch", about = "Home network device monitor")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Scan the network for devices
    Scan {
        /// Subnet to scan (auto-detected if not provided)
        subnet: Option<String>,
    },
    /// List all known devices from the database
    List,
    /// Assign a friendly name to a device
    Name { mac: String, name: String },
    /// Continuously scan and alert on new/disappeared devices
    Watch {
        /// Subnet to scan (auto-detected if not provided)
        subnet: Option<String>,
        /// Seconds between scans
        #[arg(long, default_value_t = 60)]
        interval: u64,
    },
    /// Show full history for a device
    History { mac: String },
    /// Mark a device as flagged (suspicious)
    Flag { mac: String },
    /// Remove a device from tracking
    Forget { mac: String },
}

/// Auto-detect the local subnet by finding the default route interface and its CIDR
fn detect_subnet() -> Option<String> {
    let output = Command::new("ip")
        .args(["route", "show", "default"])
        .output()
        .ok()?;
    let route = String::from_utf8_lossy(&output.stdout);
    let iface = route
        .split_whitespace()
        .skip_while(|&w| w != "dev")
        .nth(1)?
        .to_string();

    let output = Command::new("ip")
        .args(["-4", "addr", "show", &iface])
        .output()
        .ok()?;
    let addr_out = String::from_utf8_lossy(&output.stdout);
    for line in addr_out.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("inet ") {
            let cidr = trimmed.split_whitespace().nth(1)?;
            let (ip_str, prefix) = cidr.split_once('/')?;
            let prefix_num: u32 = prefix.parse().ok()?;
            let octets: Vec<u8> = ip_str.split('.').filter_map(|o| o.parse().ok()).collect();
            if octets.len() != 4 {
                return None;
            }
            let ip_u32 = u32::from_be_bytes([octets[0], octets[1], octets[2], octets[3]]);
            let mask = if prefix_num == 0 {
                0
            } else {
                !0u32 << (32 - prefix_num)
            };
            let network = ip_u32 & mask;
            let net_bytes = network.to_be_bytes();
            return Some(format!(
                "{}.{}.{}.{}/{}",
                net_bytes[0], net_bytes[1], net_bytes[2], net_bytes[3], prefix_num
            ));
        }
    }
    None
}

/// Validate MAC address format: XX:XX:XX:XX:XX:XX (colon-separated hex bytes).
fn validate_mac(mac: &str) -> Result<(), String> {
    let parts: Vec<&str> = mac.split(':').collect();
    if parts.len() != 6
        || parts
            .iter()
            .any(|p| p.len() != 2 || u8::from_str_radix(p, 16).is_err())
    {
        return Err(format!(
            "Invalid MAC address '{}'. Expected format: XX:XX:XX:XX:XX:XX (e.g. B8:27:EB:12:34:56)",
            mac
        ));
    }
    Ok(())
}

fn require_subnet(subnet: Option<String>) -> String {
    subnet.unwrap_or_else(|| {
        detect_subnet().unwrap_or_else(|| {
            eprintln!("Could not auto-detect subnet. Please provide one explicitly.");
            std::process::exit(1);
        })
    })
}

fn main() {
    let cli = Cli::parse();

    match cli.command {
        Commands::Scan { subnet } => {
            let subnet = require_subnet(subnet);
            println!("Scanning {}...", subnet);
            let devices = match scanner::run_scan(&subnet) {
                Ok(d) => d,
                Err(e) => {
                    eprintln!("Error: {e}");
                    std::process::exit(1);
                }
            };

            let mut db = db::load_db().unwrap_or_else(|e| {
                eprintln!("Warning: could not load DB: {e}");
                Default::default()
            });
            for device in &devices {
                db::update_device(&mut db, device);
            }
            if let Err(e) = db::save_db(&db) {
                eprintln!("Warning: could not save DB: {e}");
            }

            scanner::print_scan_table(&devices, &db);
        }

        Commands::List => {
            let db = match db::load_db() {
                Ok(d) => d,
                Err(e) => {
                    eprintln!("Error: {e}");
                    std::process::exit(1);
                }
            };
            scanner::print_list_table(&db);
        }

        Commands::Name { mac, name } => {
            if let Err(e) = validate_mac(&mac) {
                eprintln!("Error: {e}");
                std::process::exit(1);
            }
            let mut db = match db::load_db() {
                Ok(d) => d,
                Err(e) => {
                    eprintln!("Error: {e}");
                    std::process::exit(1);
                }
            };
            if db::set_name(&mut db, &mac, &name) {
                if let Err(e) = db::save_db(&db) {
                    eprintln!("Error saving DB: {e}");
                    std::process::exit(1);
                }
                println!("Named {} -> \"{}\"", mac, name);
            } else {
                eprintln!("Unknown device: {}. Run 'scan' first.", mac);
                std::process::exit(1);
            }
        }

        Commands::Watch { subnet, interval } => {
            let subnet = require_subnet(subnet);

            let mut db = db::load_db().unwrap_or_else(|e| {
                eprintln!("Warning: could not load DB: {e}");
                Default::default()
            });

            // MACs known before this session started
            let session_start_macs: HashSet<String> = db.keys().cloned().collect();
            let mut last_macs: HashSet<String> = HashSet::new();

            println!(
                "Watching {} every {}s. Press Ctrl+C to stop.",
                subnet, interval
            );

            loop {
                let now = chrono::Utc::now().format("%Y-%m-%d %H:%M:%S");

                match scanner::run_scan(&subnet) {
                    Ok(devices) => {
                        let current_macs: HashSet<String> = devices
                            .iter()
                            .filter(|d| !d.mac.is_empty())
                            .map(|d| d.mac.clone())
                            .collect();

                        // New = appeared in this scan but not known before session
                        let new_devices: Vec<&scanner::Device> = devices
                            .iter()
                            .filter(|d| !d.mac.is_empty() && !session_start_macs.contains(&d.mac))
                            .collect();

                        // Disappeared = was in last scan, not in this one
                        let mut disappeared: Vec<String> = last_macs
                            .iter()
                            .filter(|m| !current_macs.contains(*m))
                            .cloned()
                            .collect();
                        disappeared.sort();

                        for device in &devices {
                            db::update_device(&mut db, device);
                        }
                        if let Err(e) = db::save_db(&db) {
                            eprintln!("[{now}] Warning: could not save DB: {e}");
                        }

                        for d in &new_devices {
                            let label = if d.vendor.is_empty() {
                                String::new()
                            } else {
                                format!(" ({})", d.vendor)
                            };
                            println!(
                                "[{now}] {} New device: {} {}{}",
                                "▲".yellow().bold(),
                                d.mac,
                                d.ip,
                                label
                            );
                        }
                        for mac in &disappeared {
                            let label = db
                                .get(mac)
                                .and_then(|r| r.custom_name.as_deref())
                                .map(|n| format!(" \"{}\"", n))
                                .unwrap_or_default();
                            println!("[{now}] {} Device gone: {}{}", "▼".red(), mac, label);
                        }

                        let summary = format!(
                            "{} devices, {} new, {} disappeared",
                            current_macs.len(),
                            new_devices.len(),
                            disappeared.len()
                        );
                        if new_devices.is_empty() && disappeared.is_empty() {
                            println!("[{now}] {}", summary.dimmed());
                        } else {
                            println!("[{now}] {}", summary);
                        }

                        last_macs = current_macs;
                    }
                    Err(e) => eprintln!("[{now}] Error: {e}"),
                }

                std::thread::sleep(std::time::Duration::from_secs(interval));
            }
        }

        Commands::History { mac } => {
            if let Err(e) = validate_mac(&mac) {
                eprintln!("Error: {e}");
                std::process::exit(1);
            }
            let db = match db::load_db() {
                Ok(d) => d,
                Err(e) => {
                    eprintln!("Error: {e}");
                    std::process::exit(1);
                }
            };
            match db.get(&mac) {
                None => {
                    eprintln!("Unknown device: {}", mac);
                    std::process::exit(1);
                }
                Some(r) => {
                    let fmt = |dt: &chrono::DateTime<chrono::Utc>| {
                        dt.format("%Y-%m-%d %H:%M:%S UTC").to_string()
                    };
                    println!("MAC:         {}", r.mac);
                    println!(
                        "Name:        {}",
                        r.custom_name.as_deref().unwrap_or("(none)")
                    );
                    println!("Status:      {}", r.status);
                    println!(
                        "Vendor:      {}",
                        if r.vendor.is_empty() {
                            "(unknown)"
                        } else {
                            &r.vendor
                        }
                    );
                    println!(
                        "IPs seen:    {}",
                        if r.ips_seen.is_empty() {
                            "(none)".to_string()
                        } else {
                            r.ips_seen.join(", ")
                        }
                    );
                    println!(
                        "Hostnames:   {}",
                        if r.hostnames.is_empty() {
                            "(none)".to_string()
                        } else {
                            r.hostnames.join(", ")
                        }
                    );
                    println!("First seen:  {}", fmt(&r.first_seen));
                    println!("Last seen:   {}", fmt(&r.last_seen));
                }
            }
        }

        Commands::Flag { mac } => {
            if let Err(e) = validate_mac(&mac) {
                eprintln!("Error: {e}");
                std::process::exit(1);
            }
            let mut db = match db::load_db() {
                Ok(d) => d,
                Err(e) => {
                    eprintln!("Error: {e}");
                    std::process::exit(1);
                }
            };
            if db::set_flag(&mut db, &mac) {
                if let Err(e) = db::save_db(&db) {
                    eprintln!("Error saving DB: {e}");
                    std::process::exit(1);
                }
                println!("Flagged {} as suspicious.", mac);
            } else {
                eprintln!("Unknown device: {}. Run 'scan' first.", mac);
                std::process::exit(1);
            }
        }

        Commands::Forget { mac } => {
            if let Err(e) = validate_mac(&mac) {
                eprintln!("Error: {e}");
                std::process::exit(1);
            }
            let mut db = match db::load_db() {
                Ok(d) => d,
                Err(e) => {
                    eprintln!("Error: {e}");
                    std::process::exit(1);
                }
            };
            if db::remove_device(&mut db, &mac) {
                if let Err(e) = db::save_db(&db) {
                    eprintln!("Error saving DB: {e}");
                    std::process::exit(1);
                }
                println!("Removed {} from database.", mac);
            } else {
                eprintln!("Unknown device: {}", mac);
                std::process::exit(1);
            }
        }
    }
}
