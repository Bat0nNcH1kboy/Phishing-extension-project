"""Small DNS probing helper used by the phishing detection backend.

The checker is deliberately conservative: it resolves only the hostname and
returns a compact status. It never downloads page content and it has a short
thread timeout so the browser popup does not hang while waiting for DNS.
"""
from __future__ import annotations

import ipaddress
import socket
import time
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FutureTimeoutError
from dataclasses import asdict, dataclass
from functools import lru_cache


@dataclass(frozen=True)
class DnsResult:
    domain: str
    checked: bool
    resolvable: bool | None
    addresses: tuple[str, ...]
    elapsed_ms: int
    error: str | None = None

    def to_dict(self, include_addresses: bool = False) -> dict[str, object]:
        data = asdict(self)
        if not include_addresses:
            data["addresses"] = []
        else:
            data["addresses"] = list(self.addresses)
        return data


def _is_ip_or_local(hostname: str) -> bool:
    if hostname in {"localhost", "127.0.0.1", "::1"}:
        return True
    try:
        ipaddress.ip_address(hostname)
        return True
    except ValueError:
        return False


def _resolve_sync(hostname: str) -> tuple[str, ...]:
    infos = socket.getaddrinfo(hostname, None, type=socket.SOCK_STREAM)
    addresses = sorted({info[4][0] for info in infos if info and len(info) >= 5})
    return tuple(addresses)


@lru_cache(maxsize=4096)
def resolve_domain_cached(hostname: str, timeout_seconds: float = 1.2) -> DnsResult:
    hostname = (hostname or "").strip().lower()
    started = time.perf_counter()
    if not hostname:
        return DnsResult("", False, None, tuple(), 0, "empty hostname")
    if _is_ip_or_local(hostname):
        return DnsResult(hostname, False, True, (hostname,), 0, None)

    with ThreadPoolExecutor(max_workers=1) as executor:
        future = executor.submit(_resolve_sync, hostname)
        try:
            addresses = future.result(timeout=max(float(timeout_seconds), 0.05))
            elapsed = int((time.perf_counter() - started) * 1000)
            return DnsResult(hostname, True, bool(addresses), addresses, elapsed, None)
        except FutureTimeoutError:
            elapsed = int((time.perf_counter() - started) * 1000)
            return DnsResult(hostname, True, None, tuple(), elapsed, "dns timeout")
        except socket.gaierror as exc:
            elapsed = int((time.perf_counter() - started) * 1000)
            return DnsResult(hostname, True, False, tuple(), elapsed, f"dns lookup failed: {exc}")
        except OSError as exc:
            elapsed = int((time.perf_counter() - started) * 1000)
            return DnsResult(hostname, True, None, tuple(), elapsed, f"dns error: {exc}")


def resolve_domain(hostname: str, timeout_seconds: float = 1.2) -> DnsResult:
    return resolve_domain_cached(hostname, timeout_seconds)
