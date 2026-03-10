# netwatch

A lightweight CLI tool for monitoring devices on your local network. Scans your LAN, tracks devices over time, and alerts you when new or unknown devices appear.

Built in Rust. Designed for home labs and Raspberry Pi setups.

## Features

- **Network scanning** — Discover all devices on your subnet via ARP/nmap
- **Device tracking** — Persistent JSON database with first seen / last seen timestamps
- **Device naming** — Assign friendly names to known devices
- **Watch mode** — Continuous monitoring with alerts for new and disappeared devices
- **OUI vendor lookup** — Identifies device manufacturers from MAC addresses
- **Flag suspicious devices** — Mark and track unknown devices on your network
- **Color output** — Green (known), yellow (unknown/new), red (flagged)
- **Config file** — TOML config for default subnet and watch interval
- **Export** — Dump device data as JSON or CSV

## Requirements

- Linux (tested on Raspberry Pi OS)
- [nmap](https://nmap.org/) installed (`sudo apt install nmap`)
- `sudo` access (required for ARP scanning)

## Installation

```bash
git clone https://github.com/chrisp-coding/netwatch.git
cd netwatch
cargo build --release
sudo cp target/release/netwatch /usr/local/bin/
```

## Quick Start

```bash
# Scan your network (subnet auto-detected)
sudo netwatch scan

# Name your devices
netwatch name "AA:BB:CC:DD:EE:FF" "Living Room TV"
netwatch name "11:22:33:44:55:66" "My Laptop"

# List all tracked devices
netwatch list

# Monitor continuously (scan every 30 seconds)
sudo netwatch watch --interval 30
```

## Commands

### `scan [subnet]`

Scan the network for devices. Subnet is auto-detected from your default route if not specified.

```
$ sudo netwatch scan
Scanning 192.168.1.0/24...
+--------------+-----------------+-------------------+----------------------+----------+---------+
| Name         | IP              | MAC               | Hostname             | Vendor   | Status  |
+--------------+-----------------+-------------------+----------------------+----------+---------+
| My Laptop    | 192.168.1.164   | 5C:28:86:62:BF:1F | DESKTOP-VQU3O5V.lan | Intel    | known   |
| PS5          | 192.168.1.193   | 1C:98:C1:71:80:B5 |                      | Sony     | known   |
|              | 192.168.1.120   | 28:07:08:F8:29:3C | Samsung.lan          | Samsung  | unknown |
+--------------+-----------------+-------------------+----------------------+----------+---------+
```

### `list`

Show all tracked devices from the database.

### `name <MAC> <name>`

Assign a friendly name to a device. Also marks it as "known".

### `history <MAC>`

Show full details for a device — all IPs seen, hostnames, timestamps.

### `watch [--interval <seconds>] [subnet]`

Continuous monitoring mode. Scans at the specified interval (default: 60s) and prints timestamped alerts when devices appear or disappear.

```
[2026-03-10 03:15:46] ▲ New device: 2A:C9:B2:42:AE:6A 192.168.1.127 (Unknown vendor)
[2026-03-10 03:16:48] ▼ Device gone: 28:07:08:F8:29:3C "Samsung"
```

### `flag <MAC>`

Mark a device as suspicious/flagged for closer monitoring.

### `forget <MAC>`

Remove a device from the database entirely.

### `export [--format json|csv]`

Export device database to stdout. Default format is JSON.

```bash
netwatch export --format csv > devices.csv
netwatch export --format json > devices.json
```

### `status`

Show database and config status — device counts, paths, last scan time.

```
DB path:      /home/chris/.config/netwatch/devices.json
Config path:  /home/chris/.config/netwatch/config.toml
Devices:      9 total (3 known, 5 unknown, 1 flagged)
Last scan:    2026-03-10 03:15:46 UTC
```

### `init`

Create a default config file at `~/.config/netwatch/config.toml`.

## Configuration

Config file: `~/.config/netwatch/config.toml`

```toml
# Subnet to scan (auto-detected if not set)
# subnet = "192.168.1.0/24"

# Seconds between scans in watch mode (default: 60)
# watch_interval = 60
```

CLI arguments always take priority over config values.

## Running as a Service

A systemd service file is included for running watch mode as a daemon:

```bash
sudo cp netwatch.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now netwatch
sudo journalctl -u netwatch -f  # view logs
```

## Data Storage

Device data is stored at `~/.config/netwatch/devices.json`. The database tracks:

- MAC address (primary key)
- All IPs and hostnames seen
- Vendor (from nmap + OUI fallback)
- Custom name
- First and last seen timestamps
- Status (unknown / known / flagged)

## Running Tests

```bash
cargo test
```

## License

MIT — see [LICENSE](LICENSE)
