use std::process::Command;

#[derive(Debug)]
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
            // Save previous device if we have one
            if !current_ip.is_empty() {
                devices.push(Device {
                    ip: current_ip.clone(),
                    mac: current_mac.clone(),
                    hostname: current_hostname.clone(),
                    vendor: current_vendor.clone(),
                });
            }
            // Reset for new device
            current_mac.clear();
            current_vendor.clear();

            let rest = &line["Nmap scan report for ".len()..];
            if let Some(paren) = rest.find('(') {
                // "hostname (ip)"
                current_hostname = rest[..paren].trim().to_string();
                current_ip = rest[paren + 1..].trim_end_matches(')').to_string();
            } else {
                // just "ip"
                current_ip = rest.to_string();
                current_hostname = String::new();
            }
        } else if line.starts_with("MAC Address: ") {
            let rest = &line["MAC Address: ".len()..];
            // "AA:BB:CC:DD:EE:FF (Vendor Name)"
            if let Some(paren) = rest.find('(') {
                current_mac = rest[..paren].trim().to_string();
                current_vendor = rest[paren + 1..].trim_end_matches(')').to_string();
            } else {
                current_mac = rest.trim().to_string();
                current_vendor = String::new();
            }
        }
    }

    // Don't forget the last device
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

pub fn print_table(devices: &[Device]) {
    if devices.is_empty() {
        println!("No devices found.");
        return;
    }

    let col_ip = devices.iter().map(|d| d.ip.len()).max().unwrap_or(0).max(15);
    let col_mac = devices.iter().map(|d| d.mac.len()).max().unwrap_or(0).max(17);
    let col_hostname = devices.iter().map(|d| d.hostname.len()).max().unwrap_or(0).max(8);
    let col_vendor = devices.iter().map(|d| d.vendor.len()).max().unwrap_or(0).max(6);

    let sep = format!(
        "+-{}-+-{}-+-{}-+-{}-+",
        "-".repeat(col_ip),
        "-".repeat(col_mac),
        "-".repeat(col_hostname),
        "-".repeat(col_vendor),
    );

    println!("{sep}");
    println!(
        "| {:<col_ip$} | {:<col_mac$} | {:<col_hostname$} | {:<col_vendor$} |",
        "IP", "MAC", "Hostname", "Vendor",
        col_ip = col_ip, col_mac = col_mac, col_hostname = col_hostname, col_vendor = col_vendor,
    );
    println!("{sep}");

    for d in devices {
        println!(
            "| {:<col_ip$} | {:<col_mac$} | {:<col_hostname$} | {:<col_vendor$} |",
            d.ip, d.mac, d.hostname, d.vendor,
            col_ip = col_ip, col_mac = col_mac, col_hostname = col_hostname, col_vendor = col_vendor,
        );
    }

    println!("{sep}");
    println!("{} device(s) found.", devices.len());
}
