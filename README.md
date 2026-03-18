# NetGuard

Parental internet control via ARP/NDP spoofing. A mobile-friendly web app that lets you block and unblock a target PC's internet access — on a schedule or manually — without installing anything on the target.

Runs in Docker on a Linux host with wired Ethernet. Blocks both IPv4 and IPv6.

## How It Works

### Blocking (dual-stack)

**IPv4** — ARP cache poisoning: sends spoofed ARP replies to the target PC claiming the gateway IP resolves to the Docker host's MAC. An `iptables` FORWARD DROP rule ensures intercepted traffic is dropped.

**IPv6** — NDP cache poisoning: sends spoofed ICMPv6 Neighbor Advertisements to the target claiming the gateway's link-local address resolves to the Docker host's MAC. A spoofed Router Advertisement with `lifetime=0` kills the default IPv6 route. An `ip6tables` FORWARD DROP rule provides belt-and-suspenders blocking.

### Unblocking

Stops all spoofing threads, sends corrective ARP and NDP packets to restore the real gateway MAC in the target's caches, and removes all firewall rules. On container shutdown, unblocking runs automatically to prevent permanent lockout.

### On Startup

- Discovers gateway MAC via ARP request
- Discovers target IP from `/proc/net/arp` or subnet scan
- Discovers gateway IPv6 link-local by sniffing for Router Advertisements (falls back to EUI-64 derivation from gateway MAC)
- Restores previous blocking state from SQLite

## Requirements

- Linux host with wired Ethernet on the same LAN as the target
- Docker and Docker Compose

## Quick Start

```bash
git clone https://github.com/hankel-ai/netguard.git
cd netguard
cp .env.example .env
```

Edit `.env` with your values:

```
TARGET_MAC=AA:BB:CC:DD:EE:FF   # target PC's MAC address
GATEWAY_IP=192.168.1.1         # your router's IP
INTERFACE=eth0                 # host's network interface
AUTH_PASSWORD=changeme         # web UI password
ARP_INTERVAL=2.0               # seconds between spoof packets
DB_PATH=/data/netguard.db      # SQLite path (inside container)
TZ=America/New_York            # timezone for schedules
```

Find the target's MAC address:

```bash
# If the target is online, ping it first to populate the ARP table
ping -c 1 192.168.1.100
cat /proc/net/arp | grep 192.168.1.100
```

Start the container:

```bash
docker compose up -d --build
```

Access the web UI from any device on the LAN at `http://<host-ip>:8080`.

## Web UI

Dark-themed, mobile-first dashboard with large touch targets.

- **Status indicator** — shows BLOCKED (red) or UNBLOCKED (green)
- **Block / Unblock buttons** — manual override
- **Clear Override** — returns to schedule-driven mode
- **Schedule rules** — create rules by day (weekday/weekend/individual days) and time range; supports overnight spans (e.g., 22:00-07:00)
- **Activity log** — recent block/unblock events with source (manual/schedule/system)

Status polls every 5 seconds.

## Schedule

Rules specify when internet should be **blocked**:

| Day | Start | End | Meaning |
|-----|-------|-----|---------|
| weekday | 22:00 | 07:00 | Block Mon-Fri 10 PM to 7 AM |
| weekend | 23:00 | 08:00 | Block Sat-Sun 11 PM to 8 AM |

Overnight spans (start > end) are handled correctly.

### Override Logic

- `none` — schedule controls blocking
- `block` / `unblock` — schedule ignored, manual state held
- Clearing override immediately re-evaluates the schedule

## API

All endpoints (except login) require authentication via session cookie.

| Method | Path | Description |
|--------|------|-------------|
| POST | `/api/login` | Authenticate, sets session cookie |
| GET | `/api/status` | Current block state, override, target info |
| POST | `/api/block` | Manual override: block now |
| POST | `/api/unblock` | Manual override: unblock now |
| POST | `/api/clear-override` | Return to schedule-driven mode |
| GET | `/api/schedules` | List all schedule rules |
| POST | `/api/schedules` | Create rule `{day_of_week, start_time, end_time}` |
| PUT | `/api/schedules/{id}` | Update rule |
| DELETE | `/api/schedules/{id}` | Delete rule |
| PATCH | `/api/schedules/{id}/toggle` | Enable/disable rule |
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
│   ├── scheduler.py            # APScheduler, schedule evaluation
│   ├── database.py             # aiosqlite, schema init, state/log helpers
│   └── routes/
│       ├── api.py              # JSON API endpoints
│       └── pages.py            # Serves HTML templates
├── static/
│   ├── style.css               # Dark theme, mobile-first
│   └── app.js                  # Vanilla JS dashboard
└── templates/
    ├── login.html
    └── index.html
```

### Key Design Decisions

- **`network_mode: host`** — required for Layer 2 access (ARP/NDP packets must be on the same broadcast domain)
- **`privileged: true`** — required for raw sockets (scapy) and iptables/ip6tables
- **SQLite on a named volume** — persists state and schedules across container rebuilds
- **Always unblock on shutdown** — prevents permanent lockout if the container stops
- **NDP spoofing to ff02::1** — Windows uses randomized IPv6 interface IDs (not EUI-64), so NAs must target all-nodes multicast rather than a derived link-local address

## Troubleshooting

**Container won't start / scapy errors:**
Ensure the container runs with `privileged: true` and `network_mode: host`.

**Target not discovered:**
Make sure the target is online and on the same subnet. Ping it from the host first to populate the ARP table.

**IPv4 blocks but IPv6 doesn't:**
Check that the gateway MAC was discovered correctly in the logs. The NDP spoof derives the gateway's IPv6 link-local from its MAC via EUI-64.

**Blocking doesn't take effect immediately:**
The target caches ARP/NDP entries. It may take a few seconds for the poisoned entries to override the cache. The spoof interval (default 2s) keeps refreshing them.

**Internet not restored after unblock:**
Corrective packets are sent on unblock, but if they're lost, run `arp -d *` on the target (Windows) or wait for the cache to expire naturally (usually < 60s).

**Logs show "Could not sniff RA":**
The container falls back to deriving the gateway's IPv6 link-local from its MAC. This works for most consumer routers. If your router uses a non-EUI-64 link-local, you may need to check `ip -6 neigh` on the host and adjust.
