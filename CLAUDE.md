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
- **Auth:** None in-app. Access is gated upstream by Authentik ForwardAuth via lanward (`netguard.hankel.ai`). The container must not be exposed without that ingress in front of it — there is no other access control.

## Key Files

- `app/main.py` — FastAPI app, lifespan (startup restore + shutdown cleanup)
- `app/arp.py` — TargetBlocker (per-device ARP spoof + firewall), BlockerManager
- `app/pihole.py` — PiHoleClient (Pi-hole v6 API: groups, clients, DNS blocking)
- `app/routes/api.py` — All REST API endpoints
- `app/scheduler.py` — Schedule evaluation, 60s tick loop (also expires time-bound overrides)
- `app/database.py` — SQLite schema and queries
- `app/scanner.py` — LAN device discovery (ARP scan + DHCP leases)
- `static/app.js` — Frontend SPA
- `.env` — Config (gateway IP, interface, auth password, Pi-hole URL)

## Network

- Gateway/Router: 192.168.1.254
- Pi/Pi-hole: 192.168.1.20 (DHCP server + DNS)
- Interface: eth0
- Pi-hole URL: http://192.168.1.20 (no password)
- NetGuard container runs on same Pi as Pi-hole

## Build / Run / Test

- `rebuild.sh` — stop, rebuild, start (run on Pi only)
- `docker compose logs -f` — check logs (on Pi only)
- No test suite currently

## Override model

`targets.override` is `none` / `block` / `unblock` and tells the scheduler tick to leave the target alone. `targets.override_until` (UTC, "YYYY-MM-DD HH:MM:SS") makes the override time-bound:

- `POST /api/targets/{id}/unblock?hours=N` — UNBLOCK and auto-clear after N hours
- `POST /api/targets/{id}/unblock` (no hours) — indefinite UNBLOCK override
- `POST /api/targets/{id}/block` — BLOCK override is always indefinite (clears `override_until`)
- The 60s scheduler tick calls `clear_expired_overrides()` first; once cleared, the normal schedule re-evaluation re-applies block/unblock as needed.
- Frontend prompts for hours on UNBLOCK click and renders an "expires in Xh Ym" badge from `override_until`.
