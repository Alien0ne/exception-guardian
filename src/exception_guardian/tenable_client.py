"""Minimal Tenable Vulnerability Management client: recast/accept rules, exclusions, assets."""
from __future__ import annotations

import json
import os
import time
from typing import Callable
from urllib.parse import quote

import requests

from . import __version__
from .cves import find_cves

RETRY_CODES = {429, 500, 502, 503, 504}
BACKOFF = (1, 2, 4)
# Tenable asks every integration to identify itself: https://developer.tenable.com/docs/user-agent-header
USER_AGENT = f"Integration/1.0 (wh0-Kn0w5; Exception Guardian; Build/{__version__})"
# Fields of the "Update recast rule" body. PUT replaces the rule, so every field is sent back with
# disabled_details.disabled = true. https://developer.tenable.com/reference/recast-rules-update
_PUT_FIELDS = ("resource_type", "rule_value", "filter", "rule_name", "description", "expires_at")
_RECAST_CHANGE = ("VM.VM_RECAST.VM_RECAST.EDIT", "VM.VM_RECAST.VM_RECAST.DISABLE")
_FINGERPRINT = ("filter", "rule_value", "expires_at")


def rule_fingerprint(rule: dict) -> str:
    """What a rule hides and until when: if any of it changes, the grade and the person's yes no longer apply."""
    return json.dumps({k: rule.get(k) for k in _FINGERPRINT}, sort_keys=True, default=str)


class TenableVMClient:
    def __init__(self, base_url: str, access_key: str, secret_key: str,
                 sleep: Callable[[float], None] = time.sleep, timeout: float = 30):
        self.base_url = base_url.rstrip("/")
        self.session = requests.Session()
        self.session.headers.update({"X-ApiKeys": f"accessKey={access_key};secretKey={secret_key}",
                                     "Accept": "application/json", "User-Agent": USER_AGENT})
        self.page_size = 200
        self._sleep, self._timeout = sleep, timeout

    @classmethod
    def from_env(cls, base_url: str) -> "TenableVMClient":
        keys = {}
        for var in ("TENABLE_ACCESS_KEY", "TENABLE_SECRET_KEY"):
            if not os.environ.get(var):
                raise RuntimeError(f"environment variable {var} is not set")
            keys[var] = os.environ[var]
        return cls(base_url, keys["TENABLE_ACCESS_KEY"], keys["TENABLE_SECRET_KEY"])

    def _call(self, method: str, path: str, **kw) -> dict:
        for attempt in range(len(BACKOFF) + 1):
            try:
                resp = self.session.request(method, self.base_url + path, timeout=self._timeout, **kw)
            except (requests.ConnectionError, requests.Timeout):
                # a read the server dropped is safe to send again (8 lookups at once, a shared lab drops one now
                # and then). PUT, the only write (it disables a rule), is never sent twice
                if method == "PUT" or attempt >= len(BACKOFF):
                    raise
                self._sleep(BACKOFF[attempt])
                continue
            if resp.status_code in RETRY_CODES and attempt < len(BACKOFF):
                self._sleep(BACKOFF[attempt])
                continue
            resp.raise_for_status()
            return resp.json()
        raise AssertionError("unreachable")

    @staticmethod
    def _with_status(rule: dict) -> dict:
        disabled = bool((rule.get("disabled_details") or {}).get("disabled"))
        return {**rule, "status": "disabled" if disabled else "enabled"}

    MAX_PAGES = 1000  # a guard against a server that never ends its pages

    @classmethod
    def _next(cls, page: dict, seen: set, what: str):
        nxt = (page.get("pagination") or {}).get("next")
        if nxt and nxt in seen:
            raise RuntimeError(f"{what}: the server sent the same page token twice, so paging stopped")
        if len(seen) >= cls.MAX_PAGES:
            raise RuntimeError(f"{what}: more than {cls.MAX_PAGES} pages, so paging stopped")
        if nxt:
            seen.add(nxt)
        return nxt

    def search_rules(self) -> list[dict]:
        rules, nxt, seen = [], None, set()
        while True:
            body = {"limit": self.page_size, **({"next": nxt} if nxt else {})}
            page = self._call("POST", "/v1/recast/rules/search", json=body)
            rules += page.get("rules", [])
            nxt = self._next(page, seen, "rule search")
            if not nxt:
                return rules

    @staticmethod
    def _rule_path(rule_id: str) -> str:
        return "/v1/recast/rules/" + quote(str(rule_id), safe="")

    def get_rule(self, rule_id: str) -> dict:
        return self._with_status(self._call("GET", self._rule_path(rule_id)))

    def can_edit_rules(self) -> tuple[bool, str]:
        """Read-only check before apply, from GET /session. A custom role is a list of privilege strings in
        `user_permissions` (developer.tenable.com/docs/roles); changing a recast/accept rule needs
        VM.VM_RECAST.VM_RECAST.EDIT or .DISABLE. The `permissions` number covers only the built-in roles: a custom
        role reads 0 there even when it can change rules (seen on a live tenant), so it is used only when the
        session has no privilege list."""
        session = self._call("GET", "/session") or {}
        privileges = session.get("user_permissions")
        if isinstance(privileges, list):
            held = [p for p in _RECAST_CHANGE if p in privileges]
            if held:
                return True, f"the key's role holds {', '.join(held)}"
            return False, (f"the key's role has neither {' nor '.join(_RECAST_CHANGE)}, so it cannot change "
                           "recast/accept rules")
        role = int(session.get("permissions") or 0)
        if role >= 40:
            return True, "administrator role" if role >= 64 else "scan manager role"
        return True, "the role's privileges are not known. Tenable decides at each change"

    def disable_rule(self, rule_id: str, reason: str = "revoked via Exception Guardian",
                     expected: str | None = None) -> dict:
        current = self._call("GET", self._rule_path(rule_id))
        if expected is not None and rule_fingerprint(current) != expected:
            raise RuntimeError("the rule changed while you were confirming, so it was not disabled. Grade it again")
        body = {k: current[k] for k in _PUT_FIELDS if current.get(k) is not None}
        body["disabled_details"] = {"disabled": True, "disabled_reason": reason}
        return self._with_status(self._call("PUT", self._rule_path(rule_id), json=body))

    def plugin_cves(self, plugin_id: str) -> tuple[str, ...]:
        """CVEs of a plugin: GET /plugins/plugin/{id} (https://developer.tenable.com/reference/io-plugins-details).
        CVEs are read from every attribute value, so both repeated `cve` attributes and other layouts work."""
        data = self._call("GET", "/plugins/plugin/" + quote(str(plugin_id), safe=""))
        cves: list[str] = []
        for a in data.get("attributes", []):
            cves += [c for c in find_cves(str(a.get("attribute_value", ""))) if c not in cves]
        return tuple(cves)

    def was_plugin_cves(self, plugin_id: str) -> tuple[str, ...]:
        """CVEs of a web app scanning plugin: GET /was/v2/plugins/{id}, its `cves` list. Web app plugins are not
        served by /plugins/plugin/{id} (that call never answers for them); confirmed against a live tenant."""
        data = self._call("GET", "/was/v2/plugins/" + quote(str(plugin_id), safe=""))
        cves: list[str] = []
        for c in data.get("cves") or []:
            cves += [x for x in find_cves(str(c)) if x not in cves]
        return tuple(cves)

    def count_rule_findings(self, rule: dict, max_pages: int = 25) -> tuple[int, bool]:
        """How many findings this accept/recast rule changes today, so how many disabling it re-surfaces.
        Sends the rule's own filter, plus risk_modified ACCEPTED or RECASTED, to the v3 findings search (host or
        webapp, by the rule's resource_type) and counts the pages: at most 200 per page, `next` sent back in the body.
        Returns (count, capped); capped means it stopped after max_pages and the real number is higher.
        Endpoint, filters and paging confirmed against a live tenant."""
        kind = "webapp" if rule.get("resource_type") == "WEBAPP" else "host"
        risk = {"ACCEPT": "ACCEPTED", "RECAST": "RECASTED"}[(rule.get("rule_value") or {}).get("action", "ACCEPT")]
        flt = {"and": [rule.get("filter") or {"and": []}, {"property": "risk_modified", "operator": "eq", "value": [risk]}]}
        n, nxt = 0, None
        for _ in range(max_pages):
            body = {"limit": 200, "filter": flt, "fields": ["risk_modified"], **({"next": nxt} if nxt else {})}
            page = self._call("POST", f"/api/v3/findings/vulnerabilities/{kind}/search", json=body)
            n += len(page.get("findings") or [])
            nxt = (page.get("pagination") or {}).get("next")
            if not nxt:
                return n, False
        return n, True

    def list_exclusions(self) -> list[dict]:
        return self._call("GET", "/exclusions").get("exclusions", [])

    def list_webapps(self) -> list[dict]:
        """Web app assets: POST /api/v3/assets/webapp/search, 200 per page, `next` sent back in the body.
        Confirmed against a live tenant."""
        out, nxt, seen = [], None, set()
        while True:
            page = self._call("POST", "/api/v3/assets/webapp/search", json={"limit": 200, **({"next": nxt} if nxt else {})})
            out += page.get("assets") or []
            nxt = self._next(page, seen, "web app search")
            if not nxt:
                return out

    def asset_context(self, asset_id: str) -> dict | None:
        """ACR, AES and attack-path counts for one asset. Tenable One inventory first: its id is the VM asset id,
        and a simple text query on the id finds it (confirmed against a live tenant). Without Tenable One
        (403/404), the VM asset itself, which carries acr_score and exposure_score. None if neither knows it."""
        try:
            page = self._call("POST", "/api/v1/t1/inventory/assets/search?limit=2&extra_properties="
                              "apa_asset_total_paths_count,apa_asset_critical_paths_count",
                              json={"query": {"text": asset_id, "mode": "simple"}})
        except requests.HTTPError as exc:
            if exc.response is None or exc.response.status_code not in (403, 404):
                raise
        else:
            for item in page.get("data") or []:
                if str(item.get("id")) == asset_id:
                    extra = item.get("extra_properties") or {}
                    return {"acr": item.get("acr"), "aes": item.get("aes"),
                            "paths": extra.get("apa_asset_total_paths_count"),
                            "critical_paths": extra.get("apa_asset_critical_paths_count"),
                            "source": "Tenable One inventory"}
            return None
        try:
            a = self._call("GET", "/assets/" + quote(str(asset_id), safe=""))
        except requests.HTTPError as exc:
            if exc.response is not None and exc.response.status_code == 404:
                return None
            raise
        return {"acr": a.get("acr_score"), "aes": a.get("exposure_score"), "paths": None, "critical_paths": None,
                "source": "Tenable VM asset"}

    def asset_tags(self, asset_id: str) -> list[str]:
        """Tags as key:value from the single-asset record. On some tenants the asset list carries no tags at all
        (4 Nov 2026), so the Exposure:Internet tag is only seen here."""
        d = self._call("GET", "/assets/" + quote(str(asset_id), safe="")) or {}
        info = d.get("info", d)
        return [f"{t['tag_key']}:{t['tag_value']}" for t in info.get("tags") or [] if t.get("tag_key")]

    def attack_paths(self, max_pages: int = 20) -> tuple[list[dict], bool] | None:
        """Tenable One top attack paths, every page (100 per page, the API's minimum). (paths, capped), or None when
        the tenant has no Tenable One (403/404)."""
        out: list[dict] = []
        for page in range(max_pages):
            try:
                d = self._call("POST", f"/api/v1/t1/apa/top-attack-paths/search?limit=100&offset={page * 100}", json={})
            except requests.HTTPError as exc:
                if page == 0 and exc.response is not None and exc.response.status_code in (403, 404):
                    return None
                raise
            out += d.get("data") or []
            total = (d.get("pagination") or {}).get("total")
            if not d.get("data") or (total is not None and len(out) >= total):
                return out, False
        return out, True

    def asset_plugin_ids(self, asset_id: str) -> set[str]:
        """The plugins that reported on one asset (GET, the vulnerability workbench): DC discovery reads them."""
        data = self._call("GET", f"/workbenches/assets/{quote(asset_id, safe='')}/vulnerabilities")
        return {str(v["plugin_id"]) for v in data.get("vulnerabilities") or [] if v.get("plugin_id") is not None}

    def plugin_output(self, asset_id: str, plugin_id: str) -> str:
        """What one plugin printed for one asset (GET), every output joined."""
        data = self._call("GET", f"/workbenches/assets/{quote(asset_id, safe='')}/vulnerabilities/"
                                 f"{quote(str(plugin_id), safe='')}/outputs")
        return "\n".join(o.get("plugin_output") or "" for o in data.get("outputs") or [])

    ASSET_LIST_CAP = 5000  # GET /assets "Lists up to 5,000 assets" (developer.tenable.com/reference/assets-list-assets)

    def list_assets_with_total(self) -> tuple[list[dict], int | None]:
        """GET /assets: licensed hosts seen in the last 90 days, at most 5,000, with tags, FQDNs and OS."""
        data = self._call("GET", "/assets")
        return data.get("assets", []), data.get("total")

    def list_assets(self) -> list[dict]:
        return self.list_assets_with_total()[0]

    def list_hosts_v3(self, max_pages: int = 250) -> tuple[list[dict], bool]:
        """Every host with findings: POST /api/v3/assets/host/search, 200 per page, `next` in the body. It returns
        no tags, FQDNs or OS (the search takes no field list). Returns (rows, capped). On a live tenant it
        found several times more hosts than /assets."""
        out, nxt = [], None
        for _ in range(max_pages):
            page = self._call("POST", "/api/v3/assets/host/search", json={"limit": 200, **({"next": nxt} if nxt else {})})
            out += page.get("assets") or []
            nxt = (page.get("pagination") or {}).get("next")
            if not nxt:
                return out, False
        return out, True
