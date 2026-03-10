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
    /// List all known devices
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
    // Get the default route interface
    let output = Command::new("ip")
        .args(["route", "show", "default"])
        .output()
        .ok()?;
    let route = String::from_utf8_lossy(&output.stdout);
    // e.g. "default via 192.168.1.254 dev eth0 ..."
    let iface = route.split_whitespace()
        .skip_while(|&w| w != "dev")
        .nth(1)?
        .to_string();

    // Get the IPv4 address + prefix for that interface
    let output = Command::new("ip")
        .args(["-4", "addr", "show", &iface])
        .output()
        .ok()?;
    let addr_out = String::from_utf8_lossy(&output.stdout);
    // Find line like "    inet 192.168.1.2/24 ..."
    for line in addr_out.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("inet ") {
            let cidr = trimmed.split_whitespace().nth(1)?;
            // Convert host address to network: 192.168.1.2/24 -> 192.168.1.0/24
            let (ip_str, prefix) = cidr.split_once('/')?;
            let prefix_num: u32 = prefix.parse().ok()?;
            let octets: Vec<u8> = ip_str.split('.')
                .filter_map(|o| o.parse().ok())
                .collect();
            if octets.len() != 4 { return None; }
            let ip_u32 = u32::from_be_bytes([octets[0], octets[1], octets[2], octets[3]]);
            let mask = if prefix_num == 0 { 0 } else { !0u32 << (32 - prefix_num) };
            let network = ip_u32 & mask;
            let net_bytes = network.to_be_bytes();
            return Some(format!("{}.{}.{}.{}/{}", net_bytes[0], net_bytes[1], net_bytes[2], net_bytes[3], prefix_num));
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
            match scanner::run_scan(&subnet) {
                Ok(devices) => scanner::print_table(&devices),
                Err(e) => eprintln!("Error: {e}"),
            }
        }
        Commands::List => eprintln!("not yet implemented"),
        Commands::Name { .. } => eprintln!("not yet implemented"),
        Commands::Watch => eprintln!("not yet implemented"),
        Commands::History { .. } => eprintln!("not yet implemented"),
        Commands::Forget { .. } => eprintln!("not yet implemented"),
    }
}
