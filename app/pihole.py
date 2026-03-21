"""Pi-hole v6 API client for NetGuard integration."""

import logging
from typing import Any

import httpx

from app.config import settings

log = logging.getLogger(__name__)

_client: "PiHoleClient | None" = None


class PiHoleClient:
    """Async client for the Pi-hole v6 REST API."""

    def __init__(self, url: str, password: str | None):
        self._base = url.rstrip("/")
        self._password = password or ""
        self._sid: str | None = None
        self._no_auth = False  # True when Pi-hole has no password set
        self._http = httpx.AsyncClient(base_url=self._base, timeout=10.0)
        self._blocking_group_id: int | None = None

    # ── auth ─────────────────────────────────────────────────────

    async def _authenticate(self) -> None:
        # Logout existing session first to avoid session conflicts
        if self._sid:
            try:
                await self._http.delete(
                    "/api/auth", headers={"X-FTL-SID": self._sid}
                )
            except Exception:
                pass
            self._sid = None

        resp = await self._http.post(
            "/api/auth", json={"password": self._password}
        )
        resp.raise_for_status()
        data = resp.json()
        session = data.get("session", {})
        if not session.get("valid"):
            raise RuntimeError("Pi-hole authentication failed")
        sid = session.get("sid")
        if sid and isinstance(sid, str):
            self._sid = sid
            self._no_auth = False
            log.info("Authenticated with Pi-hole (SID=%s...)", sid[:8])
        else:
            # No password set — API is open, no SID needed
            self._no_auth = True
            log.info("Pi-hole has no password — using open API access")

    async def _request(
        self, method: str, path: str, **kwargs: Any
    ) -> httpx.Response:
        if not self._no_auth and self._sid is None:
            await self._authenticate()
        headers = kwargs.pop("headers", {})
        if self._sid:
            headers["X-FTL-SID"] = self._sid
        resp = await self._http.request(
            method, path, headers=headers, **kwargs
        )
        if resp.status_code == 401:
            self._sid = None
            self._no_auth = False
            await self._authenticate()
            if self._sid:
                headers["X-FTL-SID"] = self._sid
            resp = await self._http.request(
                method, path, headers=headers, **kwargs
            )
        if resp.status_code >= 400:
            log.warning("Pi-hole %s %s → %s: %s", method, path, resp.status_code, resp.text)
        resp.raise_for_status()
        return resp

    async def test_connection(self) -> bool:
        try:
            await self._authenticate()
            return True
        except Exception:
            log.warning("Pi-hole connection test failed", exc_info=True)
            return False

    async def close(self) -> None:
        try:
            if self._sid:
                await self._http.delete(
                    "/api/auth", headers={"X-FTL-SID": self._sid}
                )
        except Exception:
            pass
        await self._http.aclose()

    # ── DHCP leases ──────────────────────────────────────────────

    async def get_dhcp_leases(self) -> list[dict]:
        resp = await self._request("GET", "/api/dhcp/leases")
        data = resp.json()
        return data.get("leases", data if isinstance(data, list) else [])

    # ── DNS queries ──────────────────────────────────────────────

    async def get_queries(
        self, client_ip: str | None = None, limit: int = 100
    ) -> list[dict]:
        # Fetch more than needed so we have enough after filtering
        fetch_limit = limit * 5 if client_ip else limit
        params: dict[str, Any] = {"length": fetch_limit}
        if client_ip:
            params["client"] = client_ip
        resp = await self._request("GET", "/api/queries", params=params)
        data = resp.json()
        queries = data.get("queries", data if isinstance(data, list) else [])

        # Pi-hole may ignore the client param — filter ourselves
        if client_ip and queries:
            def _match(q):
                c = q.get("client")
                if isinstance(c, dict):
                    return c.get("ip") == client_ip
                if isinstance(c, str):
                    return c == client_ip
                return q.get("client_ip") == client_ip
            queries = [q for q in queries if _match(q)][:limit]

        return queries

    # ── groups ───────────────────────────────────────────────────

    async def get_groups(self) -> list[dict]:
        resp = await self._request("GET", "/api/groups")
        data = resp.json()
        return data.get("groups", data if isinstance(data, list) else [])

    async def add_group(self, name: str, description: str = "") -> dict:
        resp = await self._request(
            "POST",
            "/api/groups",
            json={"name": name, "comment": description, "enabled": True},
        )
        return resp.json()

    async def delete_group(self, name: str) -> None:
        await self._request("DELETE", f"/api/groups/{name}")

    # ── clients ──────────────────────────────────────────────────

    async def get_clients(self) -> list[dict]:
        resp = await self._request("GET", "/api/clients")
        data = resp.json()
        return data.get("clients", data if isinstance(data, list) else [])

    async def add_or_update_client(
        self, ip: str, groups: list[int], comment: str = ""
    ) -> dict:
        resp = await self._request(
            "POST",
            "/api/clients",
            json={"client": ip, "groups": groups, "comment": comment},
        )
        return resp.json()

    async def delete_client(self, ip: str) -> None:
        await self._request("DELETE", f"/api/clients/{ip}")

    # ── domains (deny/allow) ─────────────────────────────────────

    async def get_deny_regex(self) -> list[dict]:
        resp = await self._request("GET", "/api/domains/deny/regex")
        data = resp.json()
        return data.get("domains", data if isinstance(data, list) else [])

    async def add_deny_regex(
        self, pattern: str, groups: list[int], comment: str = ""
    ) -> dict:
        resp = await self._request(
            "POST",
            "/api/domains/deny/regex",
            json={
                "domain": pattern,
                "groups": groups,
                "comment": comment,
                "enabled": True,
            },
        )
        return resp.json()

    async def delete_deny_regex(self, pattern: str) -> None:
        await self._request("DELETE", f"/api/domains/deny/regex/{pattern}")

    # ── DNS blocking (NetGuard-specific) ─────────────────────────

    async def ensure_blocking_group(self) -> int:
        """Create the NetGuard-Blocked group and wildcard deny if missing.
        Returns the group ID."""
        groups = await self.get_groups()
        group = next(
            (g for g in groups if g.get("name") == "NetGuard-Blocked"), None
        )
        if group is None:
            result = await self.add_group(
                "NetGuard-Blocked",
                "Devices blocked by NetGuard — all DNS denied",
            )
            group = result.get("group", result)
            group_id = group.get("id")
            if group_id is None:
                groups = await self.get_groups()
                group = next(
                    g for g in groups if g.get("name") == "NetGuard-Blocked"
                )
                group_id = group["id"]
            log.info("Created Pi-hole group NetGuard-Blocked (id=%s)", group_id)
        else:
            group_id = group["id"]
            log.info(
                "Pi-hole group NetGuard-Blocked already exists (id=%s)",
                group_id,
            )

        # Ensure wildcard deny regex assigned to this group
        regexes = await self.get_deny_regex()
        has_wildcard = any(
            r.get("domain") == ".*"
            and group_id in r.get("groups", [])
            for r in regexes
        )
        if not has_wildcard:
            await self.add_deny_regex(
                ".*", [group_id], "NetGuard: block all DNS"
            )
            log.info("Added wildcard deny regex to NetGuard-Blocked group")

        self._blocking_group_id = group_id
        return group_id

    @property
    def blocking_group_id(self) -> int | None:
        return self._blocking_group_id

    async def dns_block_device(self, ip: str) -> None:
        """Block all DNS resolution for a device."""
        if self._blocking_group_id is None:
            await self.ensure_blocking_group()
        await self.add_or_update_client(
            ip,
            [self._blocking_group_id],
            f"Blocked by NetGuard",
        )
        log.info("DNS-blocked device %s", ip)

    async def dns_unblock_device(self, ip: str) -> None:
        """Restore DNS resolution for a device."""
        try:
            await self.delete_client(ip)
        except httpx.HTTPStatusError:
            # Client entry may not exist — reassign to default group
            await self.add_or_update_client(ip, [0])
        log.info("DNS-unblocked device %s", ip)


def get_pihole_client() -> PiHoleClient | None:
    """Return the singleton Pi-hole client, or None if not configured."""
    global _client
    if _client is not None:
        return _client
    if not settings.pihole_url:
        return None
    _client = PiHoleClient(settings.pihole_url, settings.pihole_password)
    return _client
