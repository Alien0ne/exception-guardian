"""Find the domain controllers in the scan evidence, read-only, for the SigmaHQ DC placeholders.

Several SigmaHQ rules need your DC names and addresses (%dc_machine_accounts%, %dc_ip_addresses%, ...). Unset, the
filters use a stand-in that excludes nothing. A wrong value is worse: it hides real attacks. So a DC counts only
on proof: Kerberos (plugin 43829) and LDAP (20870) answer, and either the LDAP root entry (25701) names a server
object under CN=Sites,CN=Configuration (only DCs have one) or the AD plugin (170631) reports a domain controller
role. A host with Kerberos and LDAP and no such proof is listed, unconfirmed, and never used.
"""
from __future__ import annotations

import ipaddress
import re

from .assets import parse_assets

KERBEROS, LDAP, ROOTDSE, ADCONF = "43829", "20870", "25701", "170631"
_SITES = re.compile(r"^CN=([^,]+),CN=Servers,CN=[^,]+,CN=Sites,CN=Configuration,(DC=.+)$", re.I)
_ROLE = re.compile(r"Domain Role\s*:\s*(\w*DomainController)", re.I)
PLACEHOLDER_NAMES = ("DC-MACHINE-NAME", "dc_machine_accounts", "dc_ip_addresses", "known_cdcs", "legit_ips")


def _value_after(text: str, key: str) -> str:
    """The LDAP plugin prints `[+]-key:` and the value on the next line, after `|  `."""
    lines = text.splitlines()
    for i, line in enumerate(lines):
        if line.strip().rstrip(":").endswith(f"-{key}"):
            for nxt in lines[i + 1:]:
                if nxt.strip():
                    return nxt.strip().lstrip("|").strip()
    return ""


def parse_rootdse(text: str) -> tuple[str, str]:
    return _value_after(text, "dnsHostName"), _value_after(text, "serverName")


def _usable_ips(ips) -> list[str]:
    out = []
    for ip in ips:
        try:
            if not ipaddress.ip_address(ip).is_link_local:
                out.append(ip)
        except ValueError:
            pass
    return out


def find_dcs(client) -> list[dict]:
    """Every Windows server with Kerberos and LDAP, each with its evidence and whether it is a proven DC."""
    out = []
    for a in parse_assets(client.list_assets()):
        if "windows" not in (a.os or "").lower() or "server" not in (a.os or "").lower():
            continue
        plugins = client.asset_plugin_ids(a.id)
        if not {KERBEROS, LDAP} <= plugins:
            continue
        evidence = ["Kerberos answers (plugin 43829)", "LDAP answers (plugin 20870)"]
        host, server, account, domain, confirmed = "", "", "", "", False
        if ROOTDSE in plugins:
            host, server = parse_rootdse(client.plugin_output(a.id, ROOTDSE))
            m = _SITES.match(server)
            if m:
                confirmed, account = True, f"{m.group(1).upper()}$"
                domain = ".".join(p.split("=", 1)[1] for p in m.group(2).split(","))
                evidence.append(f"LDAP names its server object in the domain's Sites (plugin 25701): {server}")
        if ADCONF in plugins:
            role = _ROLE.search(client.plugin_output(a.id, ADCONF))
            if role:
                confirmed = True
                account = account or f"{a.name.split('.')[0].upper()}$"
                evidence.append(f"Domain Role: {role.group(1)} (plugin 170631)")
        out.append({"name": a.name, "asset_id": a.id, "ips": _usable_ips(a.ips), "dns_host_name": host or
                    (a.fqdns[0] if a.fqdns else ""), "domain": domain, "account": account, "confirmed": confirmed,
                    "evidence": evidence})
    return out


def placeholders_from(dcs: list[dict]) -> dict:
    """The SigmaHQ placeholder values from the proven DCs only."""
    proven = [d for d in dcs if d.get("confirmed")]
    if not proven:
        return {}
    accounts = list(dict.fromkeys(d["account"] for d in proven if d.get("account")))
    ips = list(dict.fromkeys(ip for d in proven for ip in d.get("ips") or []))
    names = list(dict.fromkeys(d["dns_host_name"] for d in proven if d.get("dns_host_name")))
    return {"DC-MACHINE-NAME": accounts, "dc_machine_accounts": accounts, "dc_ip_addresses": ips,
            "known_cdcs": names + ips, "legit_ips": ips}
