mod scanner;

use clap::{Parser, Subcommand};

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
        /// Subnet to scan (default: 192.168.1.0/24)
        #[arg(default_value = "192.168.1.0/24")]
        subnet: String,
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

fn main() {
    let cli = Cli::parse();

    match cli.command {
        Commands::Scan { subnet } => {
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
