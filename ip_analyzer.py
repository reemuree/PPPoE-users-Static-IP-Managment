"""Pure IP classification logic. No I/O, no Flask, no RouterOS: easy to test.

Status rules (highest priority first, per IP):
    conflict            more than one enabled secret has the IP, or an active session
                        by a different user holds the IP of a secret
    reserved            excluded by the administrator
    assigned            exactly one enabled secret has the IP
    active_unconfigured an active session uses the IP, no enabled secret has it
    free / unknown      nothing known uses it (unknown when data is stale/incomplete)

"Free" only means: no known PPPoE secret, active session, conflict or reservation
uses the address. It does not prove the address is unused by other services.
Disabled secrets never claim an IP; they are reported in their own list.
"""
from __future__ import annotations

import ipaddress
from typing import Any, Iterable

ASSIGNED = "assigned"
FREE = "free"
RESERVED = "reserved"
CONFLICT = "conflict"
ACTIVE_UNCONFIGURED = "active_unconfigured"
OUT_OF_RANGE = "out_of_range"
UNKNOWN = "unknown"
ALL_STATUSES = (ASSIGNED, FREE, RESERVED, CONFLICT, ACTIVE_UNCONFIGURED, OUT_OF_RANGE, UNKNOWN)

DEFAULT_MAX_ADDRESSES = 65536
REQUIRED_KEYS = ("routes", "secrets", "active")


class AddressLimitError(ValueError):
    """Selected networks would expand to more addresses than the configured limit."""


# ---------------------------------------------------------------- parsing helpers

def _truthy(value: Any) -> bool:
    return value is True or str(value).strip().lower() in ("true", "yes")


def parse_ipv4(value: Any) -> ipaddress.IPv4Address | None:
    """Return an IPv4Address for a plain dotted address, else None (pool names, blanks...)."""
    if value is None:
        return None
    text = str(value).strip()
    if not text or "/" in text:
        return None
    try:
        return ipaddress.IPv4Address(text)
    except ValueError:
        return None


def parse_network(value: Any) -> ipaddress.IPv4Network | None:
    if value is None:
        return None
    try:
        return ipaddress.IPv4Network(str(value).strip(), strict=False)
    except ValueError:
        return None


def usable_count(net: ipaddress.IPv4Network) -> int:
    """Host addresses in a network (network and broadcast excluded for prefixes < /31)."""
    return net.num_addresses if net.prefixlen >= 31 else net.num_addresses - 2


def ip_sort_key(ip: str) -> int:
    return int(ipaddress.IPv4Address(ip))


# ---------------------------------------------------------------- route candidates

def candidate_networks(routes: Iterable[dict]) -> list[dict]:
    """Networks the admin may choose to monitor, taken from /ip/route.

    Default routes, host routes (/32, typically one per PPPoE client), multicast and
    loopback ranges are skipped. Duplicate destinations are merged.
    """
    found: dict[str, dict] = {}
    for route in routes or []:
        net = parse_network(route.get("dst-address"))
        if net is None or net.prefixlen == 0 or net.prefixlen == 32:
            continue
        if net.is_multicast or net.is_loopback or net.is_link_local:
            continue
        key = str(net)
        entry = found.get(key)
        if entry is None:
            entry = found[key] = {
                "network": key,
                "addresses": usable_count(net),
                "gateway": str(route.get("gateway") or ""),
                "comment": str(route.get("comment") or ""),
                "dynamic": _truthy(route.get("dynamic")),
                "disabled": _truthy(route.get("disabled")),
            }
        else:  # keep a useful comment/gateway if the first duplicate had none
            entry["gateway"] = entry["gateway"] or str(route.get("gateway") or "")
            entry["comment"] = entry["comment"] or str(route.get("comment") or "")
            entry["disabled"] = entry["disabled"] and _truthy(route.get("disabled"))
    return sorted(found.values(), key=lambda e: (ip_sort_key(e["network"].split("/")[0]), e["network"]))


def validate_network_list(values: Iterable[str]) -> list[str]:
    """Normalise user input to canonical CIDR strings; raise ValueError on bad entries."""
    out: list[str] = []
    for raw in values:
        net = parse_network(raw)
        if net is None or net.prefixlen == 0:
            raise ValueError(f"Invalid IPv4 network: {str(raw)[:64]!r}")
        canon = str(net)
        if canon not in out:
            out.append(canon)
    return out


def validate_reserved_list(values: Iterable[str]) -> list[str]:
    """Reserved entries may be single IPs or CIDR blocks."""
    out: list[str] = []
    for raw in values:
        text = str(raw).strip()
        if not text:
            continue
        ip = parse_ipv4(text)
        if ip is not None:
            canon = str(ip)
        else:
            net = parse_network(text)
            if net is None:
                raise ValueError(f"Invalid reserved IP/network: {text[:64]!r}")
            canon = str(net)
        if canon not in out:
            out.append(canon)
    return out


def count_addresses(networks: Iterable[str]) -> int:
    """Number of distinct usable IPs the given networks expand to (overlaps counted once)."""
    nets = [n for n in (parse_network(x) for x in networks) if n is not None and n.prefixlen > 0]
    return sum(usable_count(n) for n in _effective_networks(nets))


# ---------------------------------------------------------------- route lookup

def _route_info(route: dict, net: ipaddress.IPv4Network) -> dict:
    return {
        "dst": str(net),
        "gateway": str(route.get("gateway") or ""),
        "table": str(route.get("routing-table") or route.get("routing-mark") or "") or "main",
        "distance": route.get("distance"),
        "dynamic": _truthy(route.get("dynamic")),
    }


def _route_index(routes: Iterable[dict]):
    """Index enabled routes: /32 host routes by int(ip), other routes by network."""
    hosts: dict[int, dict] = {}
    nets: dict[ipaddress.IPv4Network, dict] = {}
    for route in routes or []:
        if _truthy(route.get("disabled")):
            continue
        net = parse_network(route.get("dst-address"))
        if net is None or net.prefixlen == 0:
            continue
        info = _route_info(route, net)
        if net.prefixlen == 32:
            hosts.setdefault(int(net.network_address), info)
        else:
            nets.setdefault(net, info)
    return hosts, nets


def _covering_route(network: ipaddress.IPv4Network, nets: dict) -> dict | None:
    """Exact route for the network, else the longest route that contains it."""
    if network in nets:
        return nets[network]
    best = None
    for cand, info in nets.items():
        if network.subnet_of(cand) and (best is None or cand.prefixlen > best[0]):
            best = (cand.prefixlen, info)
    return best[1] if best else None


# ---------------------------------------------------------------- analysis

def _effective_networks(nets: list[ipaddress.IPv4Network]) -> list[ipaddress.IPv4Network]:
    """Drop networks wholly contained in another selected one so IPs are never duplicated."""
    uniq = sorted(set(nets), key=lambda n: (int(n.network_address), n.prefixlen))
    return [n for n in uniq if not any(n != o and n.subnet_of(o) for o in uniq)]


def _empty_stats() -> dict[str, Any]:
    return {
        "total_ips": 0,
        "assigned": 0,
        "free": 0,
        "reserved": 0,
        "conflicts": 0,
        "active_unconfigured": 0,
        "unknown": 0,
        "active_users": 0,
        "offline_assigned": 0,
        "disabled_secrets": 0,
        "out_of_range": 0,
        "dynamic_secrets": 0,
        "utilization_pct": 0.0,
    }


def analyze(
    snapshot: dict[str, Any],
    networks: Iterable[str],
    reserved: Iterable[str] = (),
    max_addresses: int = DEFAULT_MAX_ADDRESSES,
    verified: bool = True,
) -> dict[str, Any]:
    """Classify every IP in the monitored networks.

    `verified=False` (stale cache, partial data) turns would-be Free rows into Unknown.
    Raises AddressLimitError if the selection exceeds `max_addresses` usable IPs.
    """
    complete = all(isinstance(snapshot.get(k), list) for k in REQUIRED_KEYS)
    verified = bool(verified and complete)

    selected = sorted(
        {n for n in (parse_network(x) for x in networks) if n is not None and n.prefixlen > 0},
        key=lambda n: (int(n.network_address), n.prefixlen),
    )
    effective = _effective_networks(selected)
    total = sum(usable_count(n) for n in effective)
    if total > max_addresses:
        raise AddressLimitError(
            f"Selected networks contain {total:,} addresses, above the limit of "
            f"{max_addresses:,}. Select smaller networks or raise MAX_ADDRESSES."
        )
    # most specific first, for labelling each IP with its tightest selected network
    by_specificity = sorted(selected, key=lambda n: -n.prefixlen)

    # reservations: single IPs as ints, blocks as (start, end) ranges
    reserved_ips: set[int] = set()
    reserved_ranges: list[tuple[int, int]] = []
    for item in reserved:
        ip = parse_ipv4(item)
        if ip is not None:
            reserved_ips.add(int(ip))
            continue
        net = parse_network(item)
        if net is not None:
            reserved_ranges.append((int(net.network_address), int(net.broadcast_address)))

    def is_reserved(n: int) -> bool:
        return n in reserved_ips or any(lo <= n <= hi for lo, hi in reserved_ranges)

    # ---- secrets
    eligible: dict[int, list[dict]] = {}
    disabled_secrets: list[dict] = []
    dynamic_secrets = 0
    all_secret_ips: list[tuple[int, dict, bool]] = []  # (ip, secret, disabled)
    for sec in snapshot.get("secrets") or []:
        name = str(sec.get("name") or "")
        is_disabled = _truthy(sec.get("disabled"))
        ip = parse_ipv4(sec.get("remote-address"))
        if ip is None:
            dynamic_secrets += 1
        else:
            all_secret_ips.append((int(ip), sec, is_disabled))
        if is_disabled:
            continue
        if ip is not None:
            eligible.setdefault(int(ip), []).append(sec)

    # ---- active sessions
    active_by_ip: dict[int, list[dict]] = {}
    active_names: set[str] = set()
    pppoe_active = 0
    for act in snapshot.get("active") or []:
        svc = str(act.get("service") or "pppoe").lower()
        if svc == "pppoe":
            pppoe_active += 1
        active_names.add(str(act.get("name") or ""))
        ip = parse_ipv4(act.get("address"))
        if ip is not None:
            active_by_ip.setdefault(int(ip), []).append(act)

    # ---- rows (one per IP, no duplicates even with overlapping routes)
    rows: dict[int, dict] = {}
    for net in effective:
        for host in net.hosts():
            n = int(host)
            owner = next(x for x in by_specificity if host in x)
            rows[n] = {
                "ip": str(host),
                "ip_int": n,
                "status": FREE,
                "username": "",
                "profile": "",
                "secret_enabled": None,
                "session": None,
                "network": str(owner),
                "comment": "",
                "note": "",
                "users": [],
                "route": "",
                "route_dst": "",
                "route_gateway": "",
                "route_table": "",
                "route_kind": "",
            }

    host_routes, net_routes = _route_index(snapshot.get("routes"))
    net_route_cache: dict[str, dict | None] = {}

    for n, row in rows.items():
        secs = eligible.get(n, [])
        acts = active_by_ip.get(n, [])
        if secs:
            row["username"] = ", ".join(str(s.get("name") or "") for s in secs)
            row["profile"] = ", ".join(sorted({str(s.get("profile") or "") for s in secs} - {""}))
            row["secret_enabled"] = True
            row["comment"] = " | ".join(str(s.get("comment")) for s in secs if s.get("comment"))
        if len(secs) > 1:
            row["status"] = CONFLICT
            row["note"] = f"{len(secs)} enabled secrets share this IP"
        elif secs:
            name = str(secs[0].get("name") or "")
            others = [a for a in acts if str(a.get("name") or "") != name]
            if others and not any(str(a.get("name") or "") == name for a in acts):
                row["status"] = CONFLICT
                row["note"] = "Active session by " + ", ".join(
                    str(a.get("name") or "?") for a in others
                ) + " holds this IP, but it is assigned to " + name
                row["session"] = "online"
            else:
                row["status"] = ASSIGNED
                row["session"] = "online" if name in active_names else "offline"
                if row["session"] == "online" and not acts:
                    row["note"] = "Session is online on a different address"
        elif acts:
            row["status"] = ACTIVE_UNCONFIGURED
            row["username"] = ", ".join(str(a.get("name") or "") for a in acts)
            row["session"] = "online"
            row["note"] = "Active session without a matching enabled secret assignment"
        else:
            row["status"] = FREE

        row["users"] = [u for u in (x.strip() for x in row["username"].split(",")) if u]
        info, kind = host_routes.get(n), "host"
        if info is None:
            net_key = row["network"]
            if net_key not in net_route_cache:
                net_route_cache[net_key] = _covering_route(ipaddress.IPv4Network(net_key), net_routes)
            info, kind = net_route_cache[net_key], "network"
        if info:
            row["route_kind"] = kind
            row["route_dst"] = info["dst"]
            row["route_gateway"] = info["gateway"]
            row["route_table"] = info["table"]
            row["route"] = f"{info['dst']} \u2192 {info['gateway'] or 'no gateway'}"

        if is_reserved(n) and row["status"] != CONFLICT:
            who = f" (currently {row['status'].replace('_', ' ')})" if row["status"] != FREE else ""
            row["status"] = RESERVED
            row["note"] = ("Reserved by administrator" + who).strip()

        if row["status"] == FREE and not verified:
            row["status"] = UNKNOWN
            row["note"] = "Router data is stale or incomplete; cannot verify this IP"

    # ---- out-of-range and disabled reports
    full_nets = selected  # membership by full range (includes network/broadcast addresses)
    out_of_range: list[dict] = []
    for n, sec, is_disabled in all_secret_ips:
        if n in rows:
            continue
        addr = ipaddress.IPv4Address(n)
        in_net = any(addr in net for net in full_nets)
        out_of_range.append(
            {
                "username": str(sec.get("name") or ""),
                "profile": str(sec.get("profile") or ""),
                "remote_address": str(addr),
                "disabled": is_disabled,
                "comment": str(sec.get("comment") or ""),
                "reason": "Network or broadcast address of a monitored network"
                if in_net
                else "Outside all monitored networks",
            }
        )
    out_of_range.sort(key=lambda e: ip_sort_key(e["remote_address"]))

    for sec in snapshot.get("secrets") or []:
        if not _truthy(sec.get("disabled")):
            continue
        ip = parse_ipv4(sec.get("remote-address"))
        name = str(sec.get("name") or "")
        disabled_secrets.append(
            {
                "username": name,
                "profile": str(sec.get("profile") or ""),
                "remote_address": str(ip) if ip else str(sec.get("remote-address") or ""),
                "in_monitored_range": bool(ip and int(ip) in rows),
                "has_active_session": name in active_names,
                "comment": str(sec.get("comment") or ""),
            }
        )
    disabled_secrets.sort(
        key=lambda e: (parse_ipv4(e["remote_address"]) is None, e["remote_address"], e["username"])
    )

    # ---- statistics
    row_list = sorted(rows.values(), key=lambda r: r["ip_int"])
    stats = _empty_stats()
    stats["total_ips"] = len(row_list)
    per_net: dict[str, dict[str, int]] = {
        str(n): {"total": 0, "assigned": 0, "free": 0, "other": 0} for n in selected
    }
    for r in row_list:
        st = r["status"]
        bucket = {
            ASSIGNED: "assigned",
            FREE: "free",
            RESERVED: "reserved",
            CONFLICT: "conflicts",
            ACTIVE_UNCONFIGURED: "active_unconfigured",
            UNKNOWN: "unknown",
        }[st]
        stats[bucket] += 1
        if st == ASSIGNED and r["session"] == "offline":
            stats["offline_assigned"] += 1
        pn = per_net[r["network"]]
        pn["total"] += 1
        pn["assigned" if st == ASSIGNED else "free" if st == FREE else "other"] += 1
    stats["active_users"] = pppoe_active
    stats["disabled_secrets"] = len(disabled_secrets)
    stats["out_of_range"] = sum(1 for e in out_of_range if not e["disabled"])
    stats["dynamic_secrets"] = dynamic_secrets
    used = stats["assigned"] + stats["conflicts"] + stats["active_unconfigured"]
    usable = stats["total_ips"] - stats["reserved"]
    stats["utilization_pct"] = round(100.0 * used / usable, 1) if usable > 0 else 0.0

    return {
        "rows": row_list,
        "stats": stats,
        "networks": [{"network": k, **v} for k, v in per_net.items()],
        "out_of_range": out_of_range,
        "disabled_secrets": disabled_secrets,
        "verified": verified,
    }
