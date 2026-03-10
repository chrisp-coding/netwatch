# netwatch — Home Network Device Monitor

## What It Does
CLI tool that scans your local network, tracks devices over time, and alerts on new/unknown devices. Think `arp-scan` meets a persistent device inventory.

## Core Features (MVP)

### 1. Network Scanning
- ARP-based discovery on local subnet (default: auto-detect interface & subnet)
- Collect: IP, MAC, hostname (via reverse DNS), vendor (OUI lookup)
- Option to use raw sockets or shell out to `nmap -sn` as fallback

### 2. Device Database
- JSON file storage (`~/.config/netwatch/devices.json`)
- Track per device: MAC (primary key), IPs seen, hostnames, first_seen, last_seen, custom name, status (known/unknown/flagged)

### 3. CLI Commands
- `netwatch scan` — run a scan, show results, update DB, flag new devices
- `netwatch list` — show all known devices (table format)
- `netwatch name <MAC> <name>` — assign a friendly name to a device
- `netwatch watch` — continuous mode, scan every N seconds, alert on changes
- `netwatch history <MAC>` — show history for a specific device
- `netwatch forget <MAC>` — remove a device from tracking

### 4. Alerts
- Print to stdout when new device appears
- Optional: write to a log file
- Future: webhook/notification support

## Tech Stack
- **Language:** Rust (stable 1.92)
- **Key crates:**
  - `clap` — CLI argument parsing
  - `serde` / `serde_json` — serialization
  - `chrono` — timestamps
  - `tabled` or `comfy-table` — pretty table output
  - `pnet` or raw ARP — network scanning (or just parse nmap output for simplicity)
  - `dirs` — XDG config paths
- **No async needed** for MVP — scans are sequential and fast on a LAN

## Project Structure
```
netwatch/
├── Cargo.toml
├── README.md
├── src/
│   ├── main.rs          # CLI entry point (clap)
│   ├── scanner.rs       # Network scanning logic
│   ├── db.rs            # Device database (JSON read/write)
│   ├── display.rs       # Table formatting & output
│   └── oui.rs           # MAC vendor lookup (embedded or file-based)
└── data/
    └── oui_subset.txt   # Top ~1000 OUI prefixes (small, embedded)
```

## Non-Goals (for now)
- No web UI
- No async/tokio
- No cross-platform (Linux only, specifically Raspberry Pi)
- No SNMP or deep protocol analysis
- No Docker

## Build Phases

### Phase 1: Scaffold + Scan (first Claude Code task)
- Cargo project init with clap
- Implement `scan` command using nmap parsing (simpler, guaranteed to work)
- Basic stdout output

### Phase 2: Persistence + Display
- JSON device database
- `list`, `name`, `forget` commands
- Table-formatted output

### Phase 3: Watch Mode + Alerts
- `watch` command with configurable interval
- New device detection & alerting
- `history` command

### Phase 4: Polish
- OUI vendor lookup
- README with usage examples
- Error handling hardening
- Tests

## Development Notes
- Rust installed at `~/.cargo/bin/` (needs PATH export)
- nmap available at `/usr/bin/nmap` (needs sudo for ARP scan)
- Pi is on 192.168.1.0/24, interface `eth0`
- Target: working tool in 4 focused Claude Code sessions
