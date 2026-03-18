# NetGuard

Parental internet control via ARP/NDP spoofing. A mobile-friendly web app that lets you block and unblock devices' internet access — on a schedule or manually — without installing anything on the targets.

Runs in Docker on a Linux host with wired Ethernet. Blocks both IPv4 and IPv6. Supports multiple targets with per-device schedules.

## How It Works

### Blocking (dual-stack)

**IPv4** — ARP cache poisoning: sends spoofed ARP replies to the target claiming the gateway IP resolves to the Docker host's MAC. An `iptables` FORWARD DROP rule ensures intercepted traffic is dropped.

**IPv6** — NDP cache poisoning: sends spoofed ICMPv6 Neighbor Advertisements to ff02::1 (all-nodes multicast) claiming the gateway's link-local address resolves to the Docker host's MAC. A spoofed Router Advertisement with `lifetime=0` kills the default IPv6 route. An `ip6tables` FORWARD DROP rule provides belt-and-suspenders blocking.

### Unblocking

Stops all spoofing threads, sends corrective ARP and NDP packets to restore the real gateway MAC in the target's caches, and removes all firewall rules. On container shutdown, all targets are unblocked automatically to prevent permanent lockout.

### On Startup

- Discovers gateway MAC via ARP request
- Discovers gateway IPv6 link-local by sniffing for Router Advertisements (falls back to EUI-64 derivation from gateway MAC)
- Restores all targets and their blocking state from SQLite

## Requirements

- Linux host with wired Ethernet on the same LAN as the targets
- Docker and Docker Compose

## Quick Start

```bash
git clone https://github.com/hankel-ai/netguard.git
cd netguard
cp .env.example .env
```

Edit `.env` with your values:

```
GATEWAY_IP=192.168.1.254       # your router's IP
INTERFACE=eth0                 # host's network interface
AUTH_PASSWORD=changeme         # web UI password
ARP_INTERVAL=2.0               # seconds between spoof packets
DB_PATH=/data/netguard.db      # SQLite path (inside container)
TZ=America/New_York            # timezone for schedules
```

Start the container:

```bash
docker compose up -d --build
```

Access the web UI from any device on the LAN at `http://<host-ip>:8080`.

## Raspberry Pi Deployment

Tested on Raspberry Pi running Debian 11 (Bullseye) arm64. These are the exact steps used to deploy from scratch.

### 1. Install Docker

SSH into the Pi and run the official Docker install script:

```bash
ssh pi@<pi-ip>
curl -fsSL https://get.docker.com -o get-docker.sh
sudo sh get-docker.sh
```

Add your user to the `docker` group so you don't need `sudo` for Docker commands:

```bash
sudo usermod -aG docker pi
```

Log out and back in (or use `sg docker -c '...'`) for the group change to take effect.

### 2. Verify Docker

```bash
docker --version
docker run --rm hello-world
```

### 3. Copy NetGuard files

From your workstation:

```bash
# Option A: git clone (if the Pi has access to the repo)
ssh pi@<pi-ip> "git clone https://github.com/hankel-ai/netguard.git ~/netguard"

# Option B: copy via tar over SSH (if git auth isn't set up)
cd netguard
tar czf - app/ static/ templates/ Dockerfile docker-compose.yml requirements.txt | \
  ssh pi@<pi-ip> "mkdir -p ~/netguard && cd ~/netguard && tar xzf -"
```

### 4. Create .env

```bash
ssh pi@<pi-ip>
cd ~/netguard
cp .env.example .env
nano .env
```

Set values for your network. Find your gateway IP with:

```bash
ip route | grep default
```

Find your network interface name with:

```bash
ip -br addr show | grep -v lo
```

Example `.env`:

```
GATEWAY_IP=192.168.1.254
INTERFACE=eth0
AUTH_PASSWORD=changeme
ARP_INTERVAL=2.0
DB_PATH=/data/netguard.db
TZ=America/New_York
```

### 5. Build and run

```bash
cd ~/netguard
docker compose up -d --build
```

First build takes a few minutes on a Pi (downloading base image + pip install). Subsequent rebuilds are much faster due to Docker layer caching.

### 6. Verify

```bash
docker logs netguard --tail 20
```

You should see:

```
NetGuard starting up...
Gateway MAC: xx:xx:xx:xx:xx:xx
Uvicorn running on http://0.0.0.0:8080
```

Access the web UI from any device on your LAN at `http://<pi-ip>:8080`.

### Updating

To deploy updates:

```bash
# From your workstation — copy changed files
tar czf - app/ static/ templates/ Dockerfile docker-compose.yml requirements.txt | \
  ssh pi@<pi-ip> "cd ~/netguard && tar xzf -"

# On the Pi — rebuild
ssh pi@<pi-ip> "cd ~/netguard && docker compose up -d --build"
```

## Web UI

Dark-themed, mobile-first dashboard with three tabs:

### Targets Tab
- **Status indicator** — BLOCKED (red) or UNBLOCKED (green) per device
- **Block / Unblock buttons** — manual override; active override button appears pressed/disabled
- **Clear** — returns to schedule-driven mode (only shown when override is active)
- **Schedule bar** — green when not in a blocking window, red when actively blocking, grayed out when overridden
- **Search** — filter targets by hostname, IP, or MAC

### LAN Devices Tab
- **Scan Now** — ARP scans the local subnet, resolves hostnames via reverse DNS and NetBIOS
- **Add** — one tap to add a discovered device as a target
- **Search** — filter scan results by hostname, IP, or MAC

### Activity Tab
- Recent block/unblock events with source (manual/schedule/system)
- Times displayed in 12-hour AM/PM format

### Adding Targets

Two ways to add targets:
1. **LAN scan** — scan your network, find the device, tap Add
2. **Manual** — enter the device's IP address; MAC and hostname are resolved automatically via ARP

## Schedule

Rules specify when internet should be **blocked**. Create per-device rules from the schedule modal (tap the schedule bar on any target card).

| Day | Start | End | Meaning |
|-----|-------|-----|---------|
| Weekdays | 10:00 PM | 7:00 AM | Block Mon-Fri overnight |
| Weekend | 11:00 PM | 8:00 AM | Block Sat-Sun overnight |

Overnight spans (start > end) are handled correctly. Rules can be individually enabled/disabled.

### Override Logic

- **No override** — schedule controls blocking
- **Block override** — internet blocked regardless of schedule
- **Unblock override** — internet open regardless of schedule
- **Clear** — removes override, immediately re-evaluates schedule

## API

All endpoints (except login) require authentication via session cookie.

| Method | Path | Description |
|--------|------|-------------|
| POST | `/api/login` | Authenticate, sets session cookie |
| GET | `/api/targets` | List all targets with status and schedules |
| POST | `/api/targets` | Add target `{ip, mac?, hostname?}` |
| DELETE | `/api/targets/{id}` | Remove target (unblocks first) |
| POST | `/api/targets/{id}/block` | Manual override: block |
| POST | `/api/targets/{id}/unblock` | Manual override: unblock |
| POST | `/api/targets/{id}/clear-override` | Return to schedule mode |
| GET | `/api/targets/{id}/schedules` | List schedules for target |
| POST | `/api/targets/{id}/schedules` | Create rule `{day_of_week, start_time, end_time}` |
| PUT | `/api/schedules/{id}` | Update rule |
| DELETE | `/api/schedules/{id}` | Delete rule |
| PATCH | `/api/schedules/{id}/toggle` | Enable/disable rule |
| POST | `/api/scan` | Scan LAN for devices |
| GET | `/api/log` | Recent audit log (last 50 entries) |

## Architecture

```
netguard/
├── docker-compose.yml          # host network, privileged, named volume
├── Dockerfile                  # python:3.11-slim + iptables + libpcap
├── .env.example
├── requirements.txt
├── app/
│   ├── main.py                 # FastAPI app, lifespan (startup/shutdown)
│   ├── config.py               # Pydantic Settings from .env
│   ├── auth.py                 # Password check, signed cookie sessions
│   ├── arp.py                  # ARP + NDP spoofing, iptables/ip6tables
│   ├── scanner.py              # LAN scanning, MAC/hostname resolution
│   ├── scheduler.py            # APScheduler, per-target schedule evaluation
│   ├── database.py             # aiosqlite, schema init, CRUD helpers
│   └── routes/
│       ├── api.py              # JSON API endpoints
│       └── pages.py            # Serves HTML templates
├── static/
│   ├── style.css               # Dark theme, mobile-first
│   └── app.js                  # Vanilla JS, tab-based dashboard
└── templates/
    ├── login.html
    └── index.html              # Three-tab SPA (Targets, LAN Devices, Activity)
```

### Key Design Decisions

- **`network_mode: host`** — required for Layer 2 access (ARP/NDP packets must be on the same broadcast domain)
- **`privileged: true`** — required for raw sockets (scapy) and iptables/ip6tables
- **SQLite on a named volume** — persists targets, schedules, and audit log across container rebuilds
- **Always unblock on shutdown** — prevents permanent lockout if the container stops
- **NDP spoofing to ff02::1** — Windows uses randomized IPv6 interface IDs (not EUI-64), so NAs must target all-nodes multicast rather than a derived link-local address
- **Per-target blockers** — each target gets its own ARP/NDP spoof threads and iptables rules

## Troubleshooting

**Container won't start / "Could not resolve gateway MAC":**
Ensure `GATEWAY_IP` and `INTERFACE` in `.env` match your network. Run `ip route | grep default` on the host to verify.

**Container won't start / scapy errors:**
Ensure the container runs with `privileged: true` and `network_mode: host`.

**"Could not resolve MAC for [ip]" when adding manually:**
The target device must be online and on the same subnet. Ping it from the host first.

**IPv4 blocks but IPv6 doesn't:**
Check that the gateway MAC was discovered correctly in the logs. The NDP spoof derives the gateway's IPv6 link-local from its MAC via EUI-64.

**Blocking doesn't take effect immediately:**
The target caches ARP/NDP entries. It may take a few seconds for the poisoned entries to override the cache. The spoof interval (default 2s) keeps refreshing them.

**Internet not restored after unblock:**
Corrective packets are sent on unblock, but if they're lost, run `arp -d *` on the target (Windows) or wait for the cache to expire naturally (usually < 60s).

**Docker Desktop on Windows/Mac:**
This app requires real Layer 2 network access and will **not** work in Docker Desktop (the container runs in a VM with its own network stack). It must run on a Linux host — a Raspberry Pi, Ubuntu server, etc.
