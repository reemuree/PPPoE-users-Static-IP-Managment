"""Read-only MikroTik RouterOS API access.

Only read operations are performed:
    /ip/route, /ppp/secret, /ppp/active, /interface (pppoe-in counters)
    and, for one user at a time, /interface/monitor-traffic (once)
Nothing here adds, sets or removes router configuration.

Run `python router_client.py` for a quick connectivity test.
"""
from __future__ import annotations

import logging
import os
import socket
import ssl
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from librouteros import connect
from librouteros.exceptions import ConnectionClosed, LibRouterosError, TrapError
from librouteros.query import Key

log = logging.getLogger(__name__)

ROUTE_FIELDS = ("dst-address", "gateway", "comment", "dynamic", "disabled", "active",
                "distance", "routing-table", "routing-mark")  # table is routing-table (v7) / routing-mark (v6)
SECRET_FIELDS = ("name", "service", "profile", "remote-address", "disabled", "comment")
ACTIVE_FIELDS = ("name", "service", "address", "caller-id", "uptime")
INTERFACE_FIELDS = ("name", "type", "running", "rx-byte", "tx-byte")


class RouterError(Exception):
    """Base class. `kind` is a short machine-readable category for the UI."""

    kind = "error"


class RouterConnectionError(RouterError):
    kind = "connection"


class RouterAuthError(RouterError):
    kind = "auth"


class RouterPermissionError(RouterError):
    kind = "permission"


class RouterConfigError(RouterError):
    kind = "config"


def _env_bool(name: str, default: bool) -> bool:
    raw = os.environ.get(name)
    if raw is None or raw.strip() == "":
        return default
    return raw.strip().lower() in ("1", "true", "yes", "on")


@dataclass(frozen=True)
class RouterConfig:
    host: str
    username: str
    password: str
    port: int = 8728
    timeout: float = 10.0
    use_ssl: bool = False
    ssl_verify: bool = False

    def __repr__(self) -> str:  # never leak the password in logs/tracebacks
        return (
            f"RouterConfig(host={self.host!r}, username={self.username!r}, "
            f"port={self.port}, timeout={self.timeout}, use_ssl={self.use_ssl})"
        )

    @classmethod
    def from_env(cls) -> "RouterConfig":
        host = os.environ.get("ROUTER_HOST", "").strip()
        username = os.environ.get("ROUTER_USER", "").strip()
        password = os.environ.get("ROUTER_PASSWORD", "")
        if not host or not username:
            raise RouterConfigError(
                "ROUTER_HOST and ROUTER_USER must be set in the server environment (.env)."
            )
        use_ssl = _env_bool("ROUTER_USE_SSL", False)
        default_port = 8729 if use_ssl else 8728
        try:
            port = int(os.environ.get("ROUTER_PORT") or default_port)
            timeout = float(os.environ.get("ROUTER_TIMEOUT") or 10)
        except ValueError as exc:
            raise RouterConfigError("ROUTER_PORT / ROUTER_TIMEOUT must be numeric.") from exc
        if not (1 <= port <= 65535) or timeout <= 0:
            raise RouterConfigError("ROUTER_PORT or ROUTER_TIMEOUT is out of range.")
        return cls(
            host=host,
            username=username,
            password=password,
            port=port,
            timeout=timeout,
            use_ssl=use_ssl,
            ssl_verify=_env_bool("ROUTER_SSL_VERIFY", False),
        )


def _ssl_wrapper(cfg: RouterConfig):
    ctx = ssl.create_default_context()
    if not cfg.ssl_verify:
        # RouterOS ships self-signed certificates; allow them unless verification is requested.
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        try:
            ctx.set_ciphers("DEFAULT:@SECLEVEL=0")  # older RouterOS uses anonymous DH
        except ssl.SSLError:
            pass
    return ctx.wrap_socket


def _read(api, path: tuple[str, ...], fields: tuple[str, ...]) -> list[dict[str, Any]]:
    return [dict(row) for row in api.path(*path).select(*fields)]


def _translate(exc: Exception, cfg: RouterConfig) -> RouterError:
    where = f"{cfg.host}:{cfg.port}"
    if isinstance(exc, TrapError):
        msg = str(exc).lower()
        if "invalid user" in msg or "cannot log in" in msg or "password" in msg:
            return RouterAuthError(f"Router {where} rejected the username or password.")
        if "not enough permissions" in msg or "permission" in msg:
            return RouterPermissionError(
                "The router user lacks permission to read routes or PPP data "
                "(needs a group with read,api policies)."
            )
        return RouterError(f"Router returned an error: {exc}")
    if isinstance(exc, ssl.SSLError):
        return RouterConnectionError(f"TLS handshake with {where} failed: {exc}")
    if isinstance(exc, (socket.timeout, TimeoutError)):
        return RouterConnectionError(f"Timed out connecting to {where}.")
    if isinstance(exc, (ConnectionClosed, LibRouterosError)):
        return RouterConnectionError(f"Connection to {where} was closed unexpectedly.")
    if isinstance(exc, OSError):
        return RouterConnectionError(f"Cannot reach router at {where}: {exc.strerror or exc}")
    return RouterError(f"Unexpected router error: {type(exc).__name__}")


def _connect(cfg: RouterConfig):
    kwargs: dict[str, Any] = dict(
        host=cfg.host,
        username=cfg.username,
        password=cfg.password,
        port=cfg.port,
        timeout=cfg.timeout,
    )
    if cfg.use_ssl:
        kwargs["ssl_wrapper"] = _ssl_wrapper(cfg)
    return connect(**kwargs)


def _close(api) -> None:
    if api is not None:
        try:
            api.close()
        except Exception:
            pass


def fetch_snapshot(cfg: RouterConfig) -> dict[str, Any]:
    """Read routes, PPP secrets, active sessions and PPPoE interface counters in one connection."""
    started = time.monotonic()
    api = None
    try:
        api = _connect(cfg)
        routes = _read(api, ("ip", "route"), ROUTE_FIELDS)
        secrets = _read(api, ("ppp", "secret"), SECRET_FIELDS)
        active = _read(api, ("ppp", "active"), ACTIVE_FIELDS)
        try:  # traffic counters are optional: a permission problem here must not break the IP view
            interfaces = [
                {k: row.get(k) for k in INTERFACE_FIELDS}
                for row in _read(api, ("interface",), INTERFACE_FIELDS)
                if str(row.get("type") or "") == "pppoe-in"
            ]
        except TrapError as exc:
            log.warning("Could not read /interface (traffic counters disabled): %s", exc)
            interfaces = None
    except RouterError:
        raise
    except Exception as exc:  # translate every library/socket failure
        raise _translate(exc, cfg) from None
    finally:
        _close(api)

    return {
        "routes": routes,
        "secrets": secrets,
        "active": active,
        "interfaces": interfaces,
        "fetched_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "duration_ms": int((time.monotonic() - started) * 1000),
    }


def _num(value: Any) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


def fetch_user_traffic(cfg: RouterConfig, iface: str) -> dict[str, Any] | None:
    """Fresh byte counters and current rate for one PPPoE interface (read-only).

    On the router's pppoe-in interface, `rx` is what the router receives from the
    client (the user's UPLOAD) and `tx` is what it sends to the client (DOWNLOAD).
    Returns None when the interface no longer exists (user went offline).
    """
    api = None
    try:
        api = _connect(cfg)
        rows = [dict(r) for r in api.path("interface").select(*INTERFACE_FIELDS).where(Key("name") == iface)]
        if not rows:
            return None
        row = rows[0]
        rate = {}
        try:
            reply = list(api.rawCmd("/interface/monitor-traffic", f"=interface={iface}", "=once="))
            rate = dict(reply[0]) if reply else {}
        except TrapError:
            rate = {}
        return {
            "interface": iface,
            "running": str(row.get("running")).lower() in ("true", "yes"),
            "download_bytes": _num(row.get("tx-byte")),
            "upload_bytes": _num(row.get("rx-byte")),
            "download_bps": _num(rate.get("tx-bits-per-second")),
            "upload_bps": _num(rate.get("rx-bits-per-second")),
            "rate_available": bool(rate),
            "fetched_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        }
    except RouterError:
        raise
    except Exception as exc:
        raise _translate(exc, cfg) from None
    finally:
        _close(api)


if __name__ == "__main__":
    try:
        from dotenv import load_dotenv

        load_dotenv()
    except ImportError:
        pass
    try:
        conf = RouterConfig.from_env()
        snap = fetch_snapshot(conf)
    except RouterError as err:
        print(f"FAILED [{err.kind}]: {err}")
        raise SystemExit(1)
    print(f"OK  {conf.host}:{conf.port}  ({snap['duration_ms']} ms)")
    print(f"  routes:         {len(snap['routes'])}")
    print(f"  ppp secrets:    {len(snap['secrets'])}")
    print(f"  active sessions:{len(snap['active'])}")
    ifs = snap.get("interfaces")
    print(f"  pppoe interfaces: {len(ifs) if ifs is not None else 'unavailable (no permission)'}")
