# netwatch

A lightweight CLI tool for monitoring devices on your local network. Scans your LAN, tracks devices over time, and alerts you when new or unknown devices appear.

Built in Rust. Designed for home labs and Raspberry Pi setups.

## Features

- **Network scanning** — Discover all devices on your subnet via ARP/nmap
- **Device tracking** — Persistent JSON database with first seen / last seen timestamps
- **Device naming & tagging** — Assign friendly names and tags (e.g. `iot`, `family`, `guest`)
- **Watch mode** — Continuous monitoring with colored alerts for new and disappeared devices
- **Scan history** — Append-only log of every scan, viewable with `netwatch log`
- **MAC randomization detection** — Identifies devices using random/private MAC addresses
- **OUI vendor lookup** — Identifies device manufacturers from MAC addresses
- **Config file** — TOML config for default subnet and watch interval
- **Export** — Dump device data as JSON or CSV
- **Color output** — Green (known), yellow (unknown/new), red (flagged)

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

# Tag devices for filtering
netwatch tag "AA:BB:CC:DD:EE:FF" iot
netwatch tag "11:22:33:44:55:66" family

# List all tracked devices (or filter by tag)
netwatch list
netwatch list --tag iot

# Monitor continuously (scan every 30 seconds)
sudo netwatch watch --interval 30
```

## Commands

| Command | Description |
|---------|-------------|
| `scan [subnet]` | Scan network for devices (subnet auto-detected) |
| `list [--tag <tag>]` | List all tracked devices, optionally filtered by tag |
| `name <MAC> <name>` | Assign a friendly name to a device |
| `tag <MAC> <tag>` | Add a tag to a device |
| `untag <MAC> <tag>` | Remove a tag from a device |
| `watch [--interval <secs>] [subnet]` | Continuous monitoring with alerts |
| `history <MAC>` | Show full details for a device |
| `flag <MAC>` | Mark a device as suspicious |
| `forget <MAC>` | Remove a device from the database |
| `log [--limit <N>]` | Show recent scan history (default: 10) |
| `export [--format json\|csv]` | Export device database to stdout |
| `status` | Show database stats, paths, device counts |
| `init` | Create default config file |

### Scan

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

### Watch Mode

```
$ sudo netwatch watch --interval 30
Watching 192.168.1.0/24 every 30s. Press Ctrl+C to stop.
[2026-03-10 03:15:46] ▲ New device: 2A:C9:B2:42:AE:6A 192.168.1.127 (random MAC)
[2026-03-10 03:16:48] ▼ Device gone: 28:07:08:F8:29:3C "Samsung"
[2026-03-10 03:17:50] 9 devices, 0 new, 0 disappeared
```

### Status

```
$ netwatch status
DB path:      /home/chris/.config/netwatch/devices.json
Config path:  /home/chris/.config/netwatch/config.toml
Devices:      9 total (3 known, 5 unknown, 1 flagged)
Last scan:    2026-03-10 03:15:46 UTC
```

## Configuration

Run `netwatch init` to create a config file at `~/.config/netwatch/config.toml`:

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

All data lives in `~/.config/netwatch/`:

| File | Purpose |
|------|---------|
| `devices.json` | Device database (MAC, IPs, names, tags, timestamps) |
| `config.toml` | User configuration |
| `scan_log.jsonl` | Append-only scan history (auto-bounded to 10K entries) |

## Development

```bash
cargo build          # build
cargo test           # run tests (36 tests)
cargo clippy         # lint
cargo fmt --check    # format check
```

CI runs automatically on push via GitHub Actions.

## License

MIT — see [LICENSE](LICENSE)
