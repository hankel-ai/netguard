"""Per-target bandwidth accounting via iptables counters."""

import logging
import re
import subprocess
import threading
import time

logger = logging.getLogger("netguard.traffic")

CHAIN = "NG_MONITOR"


class TrafficMonitor:
    """Counts per-target upload/download bytes using an iptables accounting chain."""

    def __init__(self):
        self._targets: dict[int, dict] = {}
        self._counters: dict[int, dict] = {}
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    # --- Setup / teardown ---

    def init(self):
        for cmd in ("iptables", "ip6tables"):
            subprocess.run([cmd, "-N", CHAIN], capture_output=True)
            rc = subprocess.run([cmd, "-C", "FORWARD", "-j", CHAIN],
                                capture_output=True)
            if rc.returncode != 0:
                subprocess.run([cmd, "-I", "FORWARD", "1", "-j", CHAIN],
                                capture_output=True)
        # Forwarding must be on for monitored (non-blocked) traffic to pass
        subprocess.run(["sysctl", "-w", "net.ipv4.ip_forward=1"],
                        capture_output=True)
        subprocess.run(["sysctl", "-w", "net.ipv6.conf.all.forwarding=1"],
                        capture_output=True)

    def cleanup(self):
        self.stop()
        with self._lock:
            tids = list(self._targets.keys())
        for tid in tids:
            self.remove_target(tid)
        for cmd in ("iptables", "ip6tables"):
            subprocess.run([cmd, "-F", CHAIN], capture_output=True)
            subprocess.run([cmd, "-D", "FORWARD", "-j", CHAIN],
                            capture_output=True)
            subprocess.run([cmd, "-X", CHAIN], capture_output=True)

    # --- Per-target rules ---

    def add_target(self, target_id: int, mac: str, ip: str | None):
        mac_upper = mac.upper()
        with self._lock:
            if target_id in self._targets:
                return
            self._targets[target_id] = {"mac": mac_upper, "ip": ip}
            self._counters[target_id] = {
                "tx_bytes": 0, "rx_bytes": 0,
                "tx_rate": 0.0, "rx_rate": 0.0,
                "_prev_tx": 0, "_prev_rx": 0, "_ts": time.time(),
            }
        # Upload (from device) — match source MAC
        subprocess.run([
            "iptables", "-A", CHAIN,
            "-m", "mac", "--mac-source", mac_upper,
            "-m", "comment", "--comment", f"ng_tx_{target_id}",
            "-j", "RETURN",
        ], capture_output=True)
        # Download (to device) — match dest IP
        if ip:
            subprocess.run([
                "iptables", "-A", CHAIN,
                "-d", ip,
                "-m", "comment", "--comment", f"ng_rx_{target_id}",
                "-j", "RETURN",
            ], capture_output=True)
        logger.info("Traffic rules added: target %d (%s / %s)", target_id,
                     mac_upper, ip)

    def remove_target(self, target_id: int):
        with self._lock:
            info = self._targets.pop(target_id, None)
            self._counters.pop(target_id, None)
        if not info:
            return
        subprocess.run([
            "iptables", "-D", CHAIN,
            "-m", "mac", "--mac-source", info["mac"],
            "-m", "comment", "--comment", f"ng_tx_{target_id}",
            "-j", "RETURN",
        ], capture_output=True)
        if info["ip"]:
            subprocess.run([
                "iptables", "-D", CHAIN,
                "-d", info["ip"],
                "-m", "comment", "--comment", f"ng_rx_{target_id}",
                "-j", "RETURN",
            ], capture_output=True)
        logger.info("Traffic rules removed: target %d", target_id)

    def update_ip(self, target_id: int, new_ip: str):
        with self._lock:
            info = self._targets.get(target_id)
            if not info or info["ip"] == new_ip:
                return
            old_ip = info["ip"]
            info["ip"] = new_ip
        if old_ip:
            subprocess.run([
                "iptables", "-D", CHAIN, "-d", old_ip,
                "-m", "comment", "--comment", f"ng_rx_{target_id}",
                "-j", "RETURN",
            ], capture_output=True)
        if new_ip:
            subprocess.run([
                "iptables", "-A", CHAIN, "-d", new_ip,
                "-m", "comment", "--comment", f"ng_rx_{target_id}",
                "-j", "RETURN",
            ], capture_output=True)

    # --- Counter reading ---

    def _read_counters(self):
        result = subprocess.run(
            ["iptables", "-L", CHAIN, "-v", "-x", "-n"],
            capture_output=True, text=True,
        )
        if result.returncode != 0:
            return

        now = time.time()
        tx_raw: dict[int, int] = {}
        rx_raw: dict[int, int] = {}

        for line in result.stdout.splitlines():
            parts = line.split()
            if len(parts) < 2:
                continue
            try:
                byte_count = int(parts[1])
            except ValueError:
                continue
            m_tx = re.search(r"ng_tx_(\d+)", line)
            m_rx = re.search(r"ng_rx_(\d+)", line)
            if m_tx:
                tx_raw[int(m_tx.group(1))] = byte_count
            elif m_rx:
                rx_raw[int(m_rx.group(1))] = byte_count

        with self._lock:
            for tid, ctr in self._counters.items():
                dt = now - ctr["_ts"]
                if dt <= 0:
                    continue
                new_tx = tx_raw.get(tid, ctr["_prev_tx"])
                new_rx = rx_raw.get(tid, ctr["_prev_rx"])
                dtx = max(0, new_tx - ctr["_prev_tx"])
                drx = max(0, new_rx - ctr["_prev_rx"])
                ctr["tx_rate"] = dtx / dt
                ctr["rx_rate"] = drx / dt
                ctr["tx_bytes"] += dtx
                ctr["rx_bytes"] += drx
                ctr["_prev_tx"] = new_tx
                ctr["_prev_rx"] = new_rx
                ctr["_ts"] = now

    def _loop(self):
        while not self._stop.is_set():
            try:
                self._read_counters()
            except Exception as e:
                logger.error("Traffic read error: %s", e)
            self._stop.wait(5)

    def start(self):
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()
        logger.info("Traffic monitor started")

    def stop(self):
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=10)
            self._thread = None

    # --- Public stats ---

    def get_all_stats(self) -> dict[int, dict]:
        with self._lock:
            return {
                tid: {
                    "tx_bytes": c["tx_bytes"], "rx_bytes": c["rx_bytes"],
                    "tx_rate": round(c["tx_rate"]),
                    "rx_rate": round(c["rx_rate"]),
                }
                for tid, c in self._counters.items()
            }

    def get_stats(self, target_id: int) -> dict | None:
        with self._lock:
            c = self._counters.get(target_id)
            if not c:
                return None
            return {
                "tx_bytes": c["tx_bytes"], "rx_bytes": c["rx_bytes"],
                "tx_rate": round(c["tx_rate"]),
                "rx_rate": round(c["rx_rate"]),
            }
