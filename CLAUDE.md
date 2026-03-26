# NetGuard

Network device blocker and monitor using ARP spoofing, iptables, and Pi-hole DNS blocking.

## Deployment

- **Runs on:** Raspberry Pi (192.168.1.20) — also the Pi-hole server
- **NOT on Windows/Docker Desktop** — never run docker commands locally, they hit the wrong machine
- **Deploy process:**
  1. Push changes to git from Windows
  2. SSH into Pi: `ssh pi@192.168.1.20`
  3. `cd ~/netguard && git pull`
  4. `bash rebuild.sh` (stops, rebuilds, starts container)
- Container: `netguard`, `network_mode: host`, `privileged: true`
- Data volume: `netguard-data` mounted at `/data` (SQLite DB lives here)

## Tech Stack

- **Backend:** Python 3.11, FastAPI, Uvicorn
- **ARP/Network:** Scapy (ARP spoofing, NDP), iptables/ip6tables (firewall DROP rules)
- **DNS Blocking:** Pi-hole v6 REST API (group-based, wildcard deny regex)
- **Database:** SQLite (aiosqlite), stored at `/data/netguard.db`
- **Frontend:** Vanilla JS (`static/app.js`), HTML templates (Jinja2)
- **Auth:** Simple password auth with session cookies

## Key Files

- `app/main.py` — FastAPI app, lifespan (startup restore + shutdown cleanup)
- `app/arp.py` — TargetBlocker (per-device ARP spoof + firewall), BlockerManager
- `app/pihole.py` — PiHoleClient (Pi-hole v6 API: groups, clients, DNS blocking)
- `app/routes/api.py` — All REST API endpoints
- `app/scheduler.py` — Schedule evaluation, 60s tick loop
- `app/database.py` — SQLite schema and queries
- `app/scanner.py` — LAN device discovery (ARP scan + DHCP leases)
- `static/app.js` — Frontend SPA
- `.env` — Config (gateway IP, interface, auth password, Pi-hole URL)

## Network

- Gateway: 192.168.1.254
- Pi/Pi-hole: 192.168.1.20
- Interface: eth0
- Pi-hole URL: http://192.168.1.20 (no password)

## Build / Run / Test

- `rebuild.sh` — stop, rebuild, start (run on Pi only)
- `docker compose logs -f` — check logs (on Pi only)
- No test suite currently
