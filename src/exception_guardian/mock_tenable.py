"""Local mock of the Tenable VM endpoints the client uses, served from the fixture files (for demos and tests)."""
from __future__ import annotations

import copy
import json
import re
import threading
from urllib.parse import parse_qs, urlparse
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

_RULE = re.compile(r"^/v1/recast/rules/([^/]+)$")


def _rid(raw: str) -> str:
    from urllib.parse import unquote
    return unquote(raw)


_SEARCH = re.compile(r"^/api/v3/findings/vulnerabilities/(host|webapp)/search$")


def _get(obj, dotted: str):
    for part in dotted.split("."):
        obj = obj.get(part) if isinstance(obj, dict) else None
    return obj


def _matches(finding: dict, flt: dict) -> bool:
    """The subset of the v3 filter language rules use: nested and/or, operator eq, value scalar or list."""
    if "property" in flt:
        want = flt.get("value")
        want = {str(v) for v in (want if isinstance(want, list) else [want])}
        return str(_get(finding, flt["property"])) in want
    if "or" in flt:
        return any(_matches(finding, c) for c in flt["or"])
    return all(_matches(finding, c) for c in flt.get("and", []))


def serve(fixture_dir: Path, port: int = 0, host: str = "127.0.0.1") -> tuple[ThreadingHTTPServer, str]:
    d = Path(fixture_dir)
    rules = {r["rule_id"]: r for r in copy.deepcopy(json.loads((d / "recast_rules.json").read_text())["rules"])}
    exclusions = json.loads((d / "exclusions.json").read_text())["exclusions"]
    assets = json.loads((d / "assets.json").read_text())["assets"]
    plugins_file = d / "plugins.json"
    plugins = {str(p["id"]): p for p in json.loads(plugins_file.read_text())["plugins"]} if plugins_file.exists() else {}
    was_file = d / "was_plugins.json"   # optional: web app (WAS) plugin details by id, as /was/v2/plugins/{id} returns them
    was_plugins = json.loads(was_file.read_text()) if was_file.exists() else {}
    webapps_file = d / "webapps.json"   # optional: web app assets for /api/v3/assets/webapp/search
    webapps = json.loads(webapps_file.read_text())["assets"] if webapps_file.exists() else []
    v3_file = d / "v3_hosts.json"   # optional: hosts for /api/v3/assets/host/search
    v3_hosts = json.loads(v3_file.read_text())["assets"] if v3_file.exists() else []
    findings_file = d / "findings.json"   # optional: findings for the v3 search, each with a "kind" (host/webapp)
    findings = json.loads(findings_file.read_text())["findings"] if findings_file.exists() else []
    apa_file = d / "attack_paths.json"   # optional: Tenable One attack paths; absent → the search answers 403
    apa = json.loads(apa_file.read_text())["paths"] if apa_file.exists() else None
    inv_file = d / "inventory.json"   # optional: Tenable One inventory items; absent → the search answers 403
    inventory = json.loads(inv_file.read_text())["assets"] if inv_file.exists() else None
    lock = threading.Lock()

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *a):  # keep test and demo output quiet
            pass

        def _send(self, code: int, body: dict) -> None:
            data = json.dumps(body).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def _authed(self) -> bool:
            if "accessKey=" in (self.headers.get("X-ApiKeys") or ""):
                return True
            self._send(401, {"statusCode": 401, "error": "Unauthorized", "message": "missing X-ApiKeys"})
            return False

        def _body(self) -> dict:
            n = int(self.headers.get("Content-Length") or 0)
            return json.loads(self.rfile.read(n) or b"{}")

        def do_GET(self):
            if not self._authed():
                return
            m = _RULE.match(self.path)
            if m:
                with lock:
                    r = rules.get(_rid(m.group(1)))
                return self._send(200, r) if r else self._send(404, {"statusCode": 404, "message": "not found"})
            if self.path.startswith("/plugins/plugin/"):
                p = plugins.get(self.path.rsplit("/", 1)[1])
                return self._send(200, p) if p else self._send(404, {"statusCode": 404, "message": "not found"})
            if self.path.startswith("/was/v2/plugins/"):
                p = was_plugins.get(self.path.rsplit("/", 1)[1])
                return self._send(200, p) if p else self._send(404, {"statusCode": 404, "message": "not found"})
            if self.path == "/exclusions":
                return self._send(200, {"exclusions": exclusions})
            if self.path == "/assets":
                return self._send(200, {"assets": assets, "total": len(assets)})
            if self.path.startswith("/assets/"):
                a = next((x for x in assets if x["id"] == self.path.rsplit("/", 1)[1]), None)
                return (self._send(200, {"id": a["id"], "acr_score": a.get("x_acr"), "exposure_score": a.get("x_aes")})
                        if a else self._send(404, {"statusCode": 404, "message": "not found"}))
            self._send(404, {"statusCode": 404, "message": "not found"})

        def do_POST(self):
            if not self._authed():
                return
            if self.path == "/api/v3/assets/host/search":
                body = self._body()
                limit, start = int(body.get("limit", 50)), int(body.get("next") or 0)
                nxt = {"next": str(start + limit)} if start + limit < len(v3_hosts) else {}
                return self._send(200, {"assets": v3_hosts[start:start + limit], "pagination": nxt})
            if self.path.startswith("/api/v1/t1/apa/top-attack-paths/search"):
                if apa is None:
                    return self._send(403, {"statusCode": 403, "error": "Forbidden"})
                q = parse_qs(urlparse(self.path).query)
                limit, off = int(q.get("limit", ["100"])[0]), int(q.get("offset", ["0"])[0])
                if limit < 100:   # the real API: "The requested page size must be at least 100"
                    return self._send(400, {"error": "Bad Request"})
                return self._send(200, {"data": apa[off:off + limit],
                                        "pagination": {"total": len(apa), "offset": off, "limit": limit}})
            if self.path.startswith("/api/v1/t1/inventory/assets/search"):
                if inventory is None:
                    return self._send(403, {"statusCode": 403, "error": "Forbidden"})
                text = str(((self._body().get("query") or {}).get("text")) or "")
                hits = [i for i in inventory if text and text in json.dumps(i)]
                return self._send(200, {"data": hits[:2], "pagination": {"total": len(hits)}})
            if self.path == "/api/v3/assets/webapp/search":
                return self._send(200, {"assets": webapps, "pagination": {"limit": 200, "total": len(webapps)}})
            m = _SEARCH.match(self.path)
            if m:
                return self._search_findings(m.group(1), self._body())
            if self.path != "/v1/recast/rules/search":
                return self._send(404, {"statusCode": 404, "message": "not found"})
            body = self._body()
            limit, start = int(body.get("limit", 200)), int(body.get("next") or 0)
            with lock:
                allr = list(rules.values())
            page = allr[start:start + limit]
            nxt = str(start + limit) if start + limit < len(allr) else None
            self._send(200, {"rules": page, "pagination": {"total": len(allr), "limit": limit, "next": nxt}})

        def _search_findings(self, kind: str, body: dict) -> None:
            # like the v3 findings search: limit 1-200, `total` only when one page holds everything, else `next`
            limit, start = int(body.get("limit", 50)), int(body.get("next") or 0)
            if not 1 <= limit <= 200:
                return self._send(400, {"error": "`limit` must be 1-200 inclusive"})
            hits = [f for f in findings if f.get("kind", "host") == kind and _matches(f, body.get("filter") or {})]
            page = hits[start:start + limit]
            if start == 0 and len(hits) <= limit:
                pagination = {"total": len(hits)}
            else:
                pagination = {"next": str(start + limit)} if start + limit < len(hits) else {}
            self._send(200, {"findings": page, "pagination": pagination})

        def do_PUT(self):
            if not self._authed():
                return
            m = _RULE.match(self.path)
            with lock:
                if not m or _rid(m.group(1)) not in rules:
                    return self._send(404, {"statusCode": 404, "message": "not found"})
                body, r = self._body(), rules[_rid(m.group(1))]
                for k in ("resource_type", "rule_value", "filter", "rule_name", "description", "expires_at"):
                    if k in body:
                        r[k] = body[k]
                dd = body.get("disabled_details") or {}
                now = datetime.now(timezone.utc).isoformat(timespec="seconds")
                r["disabled_details"] = ({"disabled": True, "disabled_at": now, "disabled_by": "mock-user",
                                          "disabled_reason": dd.get("disabled_reason")}
                                         if dd.get("disabled") else {"disabled": False})
                r["updated_at"] = now
                out = copy.deepcopy(r)
            self._send(200, out)

    srv = ThreadingHTTPServer((host, port), Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, f"http://{host}:{srv.server_address[1]}"
