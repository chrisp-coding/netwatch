mod db;
mod scanner;

use clap::{Parser, Subcommand};
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
    Name {
        mac: String,
        name: String,
    },
    /// Continuously scan and alert on new devices
    Watch,
    /// Show history for a device
    History {
        mac: String,
    },
    /// Remove a device from tracking
    Forget {
        mac: String,
    },
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
            let octets: Vec<u8> = ip_str
                .split('.')
                .filter_map(|o| o.parse().ok())
                .collect();
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

fn main() {
    let cli = Cli::parse();

    match cli.command {
        Commands::Scan { subnet } => {
            let subnet = subnet.unwrap_or_else(|| {
                detect_subnet().unwrap_or_else(|| {
                    eprintln!("Could not auto-detect subnet. Please provide one explicitly.");
                    std::process::exit(1);
                })
            });
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

        Commands::Forget { mac } => {
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

        Commands::Watch => eprintln!("not yet implemented"),
        Commands::History { .. } => eprintln!("not yet implemented"),
    }
}
