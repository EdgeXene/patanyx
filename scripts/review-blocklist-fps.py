#!/usr/bin/env python3
"""
PATANYX phishing-blocklist false-positive review queue.

READ-ONLY SAFETY CONTRACT
-------------------------
This script never changes the blocklist, blocklist-allow.txt, or
blocklist-confirm.txt. It emits evidence and a ranked queue; a human makes every
adjudication. Its only write is an optional, separate network-result cache.

A high score means "worth a human look", never "safe" or "unblock this".

Scoring philosophy
------------------
The score estimates review value, not legitimacy:

* Tranco rank raises the potential blast radius, but never proves innocence.
  Attackers can attract traffic, and typosquats can themselves become popular.
* A single feed is weaker evidence than corroboration. Feeds may share upstream
  reports, however, so even three feeds are not assumed fully independent.
* An apex/public-suffix-scale entry is urgent because it blocks descendants.
  That is an impact signal, not evidence that the entry is mistaken.
* Old registration age is strong only when RDAP describes the exact listed
  registered domain. Parent-domain age is never attributed to a subdomain.
  Compromised and deliberately purchased aged domains remain possible.
* A currently resolving host has more immediate user impact. NXDOMAIN does not
  prove that a historical phishing report was wrong, so it lowers priority.
* A valid organization-identified TLS certificate is weak supporting evidence.
  Ordinary DV TLS is intentionally not treated as legitimacy: attackers can
  automate it, and an attacker who knows this tool exists could do exactly that.

The thresholds deliberately use broad year-scale age bands. Phishing domains are
commonly short-lived, while a 5-, 10-, or 15-year exact registration is unusual
enough to justify review. The bands are not verdict boundaries.

Selection is bounded. The first tier is the Tranco 10,001-100,000 gap. The tail
is ordered deterministically from offline evidence and a stable hash, so
--offset can walk it reproducibly. Final scores rank the selected window, not
the entire unevaluated blocklist.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import datetime as dt
import email.utils
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import random
import re
import secrets
import socket
import ssl
import struct
import sys
import tempfile
import threading
import time
from typing import Any, Iterable
import urllib.error
import urllib.parse
import urllib.request


EXPECTED_FEEDS = (
    "Phishing.Database",
    "phishunt.io",
    "PhishDestroy",
)
CACHE_VERSION = 1
UNKNOWN = {"status": "unknown", "reason": "not looked up"}


def warn(message: str) -> None:
    print(f"warning: {message}", file=sys.stderr)


def without_comment(line: str) -> str:
    """Match the allow/confirm parser: remove # comments, trim, lowercase."""
    return line.split("#", 1)[0].strip().lower()


def normalize_host(value: str) -> str | None:
    value = value.strip().lower().rstrip(".")
    value = value.removeprefix("||").rstrip("^")
    value = value.removeprefix("*.").lstrip(".")
    if not value:
        return None

    if value.startswith("[") and "]" in value:
        value = value[1:value.index("]")]
    elif value.count(":") == 1:
        possible_host, possible_port = value.rsplit(":", 1)
        if possible_port.isdigit():
            value = possible_host

    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        pass

    try:
        value = value.encode("idna").decode("ascii").lower()
    except UnicodeError:
        return None

    if len(value) > 253 or "." not in value:
        return None
    labels = value.split(".")
    if any(
        not label
        or len(label) > 63
        or label.startswith("-")
        or label.endswith("-")
        or re.fullmatch(r"[a-z0-9_-]+", label) is None
        for label in labels
    ):
        return None
    return value


def read_simple_host_file(path: Path, required: bool = False) -> list[str]:
    hosts: list[str] = []
    seen: set[str] = set()
    try:
        with path.open("r", encoding="utf-8", errors="replace") as handle:
            for raw in handle:
                host = normalize_host(without_comment(raw))
                if host and host not in seen:
                    seen.add(host)
                    hosts.append(host)
    except FileNotFoundError:
        if required:
            raise
        warn(f"{path} not found; treating it as empty")
    except OSError as exc:
        if required:
            raise
        warn(f"could not read {path}: {exc}; treating it as empty")
    return hosts


class RuleSet:
    def __init__(self) -> None:
        self.exact: set[str] = set()
        self.wildcard_bases: set[str] = set()
        self.exceptions: set[str] = set()

    def add(self, rule: str) -> None:
        if rule.startswith("!"):
            self.exceptions.add(rule[1:])
        elif rule.startswith("*."):
            self.wildcard_bases.add(rule[2:])
        else:
            self.exact.add(rule)


class PublicSuffixList:
    """PSL matching for blast-radius boundaries and ICANN RDAP boundaries."""

    def __init__(self, path: Path) -> None:
        self.all_rules = RuleSet()
        self.icann_rules = RuleSet()
        in_private_section = False

        with path.open("r", encoding="utf-8", errors="replace") as handle:
            for raw in handle:
                marker = raw.strip()
                if "BEGIN PRIVATE DOMAINS" in marker:
                    in_private_section = True
                    continue
                if "END PRIVATE DOMAINS" in marker:
                    in_private_section = False
                    continue

                rule = raw.split("//", 1)[0].strip().lower().rstrip(".")
                if not rule:
                    continue
                try:
                    prefix = ""
                    body = rule
                    if body.startswith("!"):
                        prefix, body = "!", body[1:]
                    elif body.startswith("*."):
                        prefix, body = "*.", body[2:]
                    body = body.encode("idna").decode("ascii")
                    rule = prefix + body
                except UnicodeError:
                    continue

                self.all_rules.add(rule)
                if not in_private_section:
                    self.icann_rules.add(rule)

    @staticmethod
    def _public_suffix_length(host: str, rules: RuleSet) -> int:
        labels = host.split(".")

        exception_lengths = [
            len(suffix.split("."))
            for i in range(len(labels))
            if (suffix := ".".join(labels[i:])) in rules.exceptions
        ]
        if exception_lengths:
            # Under the PSL algorithm, an exception removes its leftmost label.
            return max(exception_lengths) - 1

        best = 1  # The implicit "*" rule.
        for i in range(len(labels)):
            suffix = ".".join(labels[i:])
            if suffix in rules.exact:
                best = max(best, len(labels) - i)
            if i + 1 < len(labels):
                wildcard_base = ".".join(labels[i + 1:])
                if wildcard_base in rules.wildcard_bases:
                    best = max(best, len(labels) - i)
        return best

    def registrable(self, host: str, include_private: bool) -> str | None:
        try:
            ipaddress.ip_address(host)
            return None
        except ValueError:
            pass
        labels = host.split(".")
        rules = self.all_rules if include_private else self.icann_rules
        suffix_len = self._public_suffix_length(host, rules)
        if len(labels) <= suffix_len:
            return None
        return ".".join(labels[-(suffix_len + 1):])

    def is_public_suffix(self, host: str) -> bool:
        try:
            ipaddress.ip_address(host)
            return False
        except ValueError:
            pass
        labels = host.split(".")
        return len(labels) == self._public_suffix_length(host, self.all_rules)


def classify_shape(host: str, psl: PublicSuffixList) -> dict[str, Any]:
    try:
        ipaddress.ip_address(host)
        return {
            "kind": "ip",
            "registrable_domain": None,
            "rdap_domain": None,
            "subdomain_depth": None,
        }
    except ValueError:
        pass

    service_domain = psl.registrable(host, include_private=True)
    rdap_domain = psl.registrable(host, include_private=False)

    if psl.is_public_suffix(host):
        kind = "public_suffix"
        depth = None
    elif service_domain is None:
        kind = "unknown_boundary"
        depth = None
    else:
        depth = len(host.split(".")) - len(service_domain.split("."))
        kind = "service_apex" if depth == 0 else "subdomain"

    return {
        "kind": kind,
        "registrable_domain": service_domain,
        "rdap_domain": rdap_domain,
        "subdomain_depth": depth,
    }


def parse_tranco_line(line: str) -> str | None:
    line = line.strip()
    if not line:
        return None
    if "," in line:
        token = line.rsplit(",", 1)[-1].strip()
    else:
        fields = line.split()
        token = fields[1] if len(fields) >= 2 and fields[0].isdigit() else fields[0]
    return normalize_host(token)


def load_tranco_coverage(
    path: Path, blockset: set[str]
) -> tuple[dict[str, int], dict[str, str], dict[str, int]]:
    """
    Attribute a Tranco hostname to every listed label-boundary ancestor that
    blocks it. This catches an apex whose popular descendant, rather than the
    apex itself, appears in Tranco.
    """
    covered_rank: dict[str, int] = {}
    covered_name: dict[str, str] = {}
    exact_rank: dict[str, int] = {}

    try:
        handle = path.open("r", encoding="utf-8", errors="replace")
    except OSError as exc:
        warn(f"could not read Tranco snapshot {path}: {exc}; popularity is unknown")
        return covered_rank, covered_name, exact_rank

    rank = 0
    with handle:
        for raw in handle:
            stripped = raw.strip()
            if not stripped or stripped.startswith("#"):
                continue
            rank += 1
            tranco_host = parse_tranco_line(stripped)
            if not tranco_host:
                continue

            if tranco_host in blockset:
                exact_rank.setdefault(tranco_host, rank)

            try:
                ipaddress.ip_address(tranco_host)
                ancestors = (tranco_host,)
            except ValueError:
                labels = tranco_host.split(".")
                ancestors = (".".join(labels[i:]) for i in range(len(labels)))

            for listed_host in ancestors:
                if listed_host not in blockset:
                    continue
                old = covered_rank.get(listed_host)
                if old is None or rank < old:
                    covered_rank[listed_host] = rank
                    covered_name[listed_host] = tranco_host

    return covered_rank, covered_name, exact_rank


def canonical_feed_name(value: str) -> str | None:
    key = re.sub(r"[^a-z0-9]", "", value.lower())
    if "phishdestroy" in key:
        return "PhishDestroy"
    if "phishunt" in key:
        return "phishunt.io"
    if "phishingdatabase" in key:
        return "Phishing.Database"
    return None


def discover_feeds(state_dir: Path) -> dict[str, Path]:
    candidates: dict[str, list[Path]] = {name: [] for name in EXPECTED_FEEDS}
    if not state_dir.is_dir():
        return {}

    try:
        walker = os.walk(state_dir)
        for directory, _, files in walker:
            for filename in files:
                path = Path(directory) / filename
                canonical = canonical_feed_name(str(path))
                if canonical:
                    candidates[canonical].append(path)
    except OSError as exc:
        warn(f"could not scan {state_dir} for feed snapshots: {exc}")
        return {}

    chosen: dict[str, Path] = {}
    for name, paths in candidates.items():
        if not paths:
            continue
        try:
            chosen[name] = max(paths, key=lambda p: p.stat().st_mtime)
        except OSError:
            chosen[name] = sorted(paths)[-1]
    return chosen


def feed_hosts(path: Path, blockset: set[str]) -> set[str]:
    """Extract exact hosts from common host-, URL-, CSV-, and adblock-style feeds."""
    found: set[str] = set()
    try:
        handle = path.open("r", encoding="utf-8", errors="replace")
    except OSError as exc:
        warn(f"could not read feed snapshot {path}: {exc}")
        return found

    with handle:
        for raw in handle:
            line = raw.split("#", 1)[0].strip()
            if not line:
                continue
            tokens = re.split(r"[\s,\t\"']+", line)
            for token in tokens:
                token = token.strip("()[]{}<>;")
                if not token:
                    continue

                host: str | None
                if "://" in token:
                    try:
                        host = urllib.parse.urlsplit(token).hostname
                    except ValueError:
                        host = None
                else:
                    token = token.removeprefix("||").rstrip("^")
                    token = token.split("/", 1)[0]
                    host = token

                normalized = normalize_host(host or "")
                # Corroboration is exact-host only. Parent or child reports are
                # not borrowed, avoiding lookalike/reputation contamination.
                if normalized in blockset:
                    found.add(normalized)
    return found


class ResultCache:
    def __init__(self, path: Path, ttl_seconds: float, protected: Iterable[Path]) -> None:
        self.path = path
        self.ttl_seconds = ttl_seconds
        self.entries: dict[str, dict[str, Any]] = {}
        self.changed = False
        self.enabled = True

        target = path.resolve(strict=False)
        protected_targets = {p.resolve(strict=False) for p in protected}
        if target in protected_targets:
            warn(f"refusing to use protected input file as cache: {path}")
            self.enabled = False
            return

        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
            if payload.get("version") == CACHE_VERSION:
                entries = payload.get("entries")
                if isinstance(entries, dict):
                    self.entries = entries
        except FileNotFoundError:
            pass
        except (OSError, ValueError, TypeError) as exc:
            warn(f"ignoring unreadable cache {path}: {exc}")

    def get(self, key: str) -> dict[str, Any] | None:
        if not self.enabled:
            return None
        record = self.entries.get(key)
        if not isinstance(record, dict):
            return None
        checked_at = record.get("checked_at")
        value = record.get("value")
        if not isinstance(checked_at, (int, float)) or not isinstance(value, dict):
            return None

        # Transient failures are cached briefly so reruns remain polite, but
        # recover much sooner than successful evidence.
        status = str(value.get("status", "unknown"))
        ttl = self.ttl_seconds
        if status in {"unknown", "error", "timeout", "rate_limited"}:
            ttl = min(ttl, 6 * 3600)
        if time.time() - checked_at > ttl:
            return None
        return value

    def set(self, key: str, value: dict[str, Any]) -> None:
        if not self.enabled or value.get("reason") == "network budget exhausted":
            return
        self.entries[key] = {"checked_at": time.time(), "value": value}
        self.changed = True

    def save(self) -> None:
        if not self.enabled or not self.changed:
            return
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            payload = {"version": CACHE_VERSION, "entries": self.entries}
            with tempfile.NamedTemporaryFile(
                "w",
                encoding="utf-8",
                dir=self.path.parent,
                prefix=self.path.name + ".",
                suffix=".tmp",
                delete=False,
            ) as handle:
                temp_name = handle.name
                json.dump(payload, handle, separators=(",", ":"), sort_keys=True)
                handle.flush()
                os.fsync(handle.fileno())
            os.chmod(temp_name, 0o600)
            os.replace(temp_name, self.path)
        except OSError as exc:
            warn(f"could not save cache {self.path}: {exc}")
            try:
                if "temp_name" in locals():
                    os.unlink(temp_name)
            except OSError:
                pass


class NetworkBudget:
    def __init__(self, limit: int) -> None:
        self.limit = max(0, limit)
        self.used = 0
        self.lock = threading.Lock()

    def reserve(self) -> bool:
        with self.lock:
            if self.used >= self.limit:
                return False
            self.used += 1
            return True


class RateLimiter:
    def __init__(self, interval: float) -> None:
        self.interval = max(0.0, interval)
        self.next_allowed = 0.0
        self.lock = threading.Lock()

    def acquire(self) -> None:
        with self.lock:
            now = time.monotonic()
            delay = max(0.0, self.next_allowed - now)
            self.next_allowed = max(now, self.next_allowed) + self.interval
        if delay:
            time.sleep(delay)

    def defer(self, seconds: float) -> None:
        with self.lock:
            self.next_allowed = max(
                self.next_allowed, time.monotonic() + max(0.0, seconds)
            )


def resolver_addresses() -> list[str]:
    result: list[str] = []
    try:
        with open("/etc/resolv.conf", "r", encoding="ascii", errors="ignore") as handle:
            for line in handle:
                fields = line.split()
                if len(fields) >= 2 and fields[0] == "nameserver":
                    try:
                        result.append(str(ipaddress.ip_address(fields[1].split("%", 1)[0])))
                    except ValueError:
                        continue
    except OSError:
        pass
    return result


def dns_name_end(packet: bytes, offset: int) -> int:
    steps = 0
    while True:
        if offset >= len(packet) or steps > 255:
            raise ValueError("malformed DNS name")
        length = packet[offset]
        if length & 0xC0 == 0xC0:
            if offset + 1 >= len(packet):
                raise ValueError("truncated DNS pointer")
            return offset + 2
        if length == 0:
            return offset + 1
        if length & 0xC0:
            raise ValueError("invalid DNS label")
        offset += 1 + length
        steps += 1


def parse_dns_response(packet: bytes, query_id: int) -> tuple[int, bool, list[str]]:
    if len(packet) < 12:
        raise ValueError("short DNS response")
    response_id, flags, qdcount, ancount, _, _ = struct.unpack("!HHHHHH", packet[:12])
    if response_id != query_id or not (flags & 0x8000):
        raise ValueError("unmatched DNS response")
    truncated = bool(flags & 0x0200)
    rcode = flags & 0x000F
    offset = 12
    for _ in range(qdcount):
        offset = dns_name_end(packet, offset)
        if offset + 4 > len(packet):
            raise ValueError("short DNS question")
        offset += 4

    addresses: list[str] = []
    for _ in range(ancount):
        offset = dns_name_end(packet, offset)
        if offset + 10 > len(packet):
            raise ValueError("short DNS answer")
        record_type, _, _, rdlength = struct.unpack("!HHIH", packet[offset:offset + 10])
        offset += 10
        if offset + rdlength > len(packet):
            raise ValueError("short DNS rdata")
        rdata = packet[offset:offset + rdlength]
        offset += rdlength
        if record_type == 1 and rdlength == 4:
            addresses.append(str(ipaddress.IPv4Address(rdata)))
        elif record_type == 28 and rdlength == 16:
            addresses.append(str(ipaddress.IPv6Address(rdata)))
    return rcode, truncated, addresses


def receive_exact(sock: socket.socket, count: int) -> bytes:
    chunks: list[bytes] = []
    remaining = count
    while remaining:
        chunk = sock.recv(remaining)
        if not chunk:
            raise OSError("unexpected EOF")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def one_dns_query(
    nameserver: str, host: str, query_type: int, timeout: float
) -> tuple[int, list[str]]:
    labels = host.encode("ascii").split(b".")
    qname = b"".join(bytes((len(label),)) + label for label in labels) + b"\x00"
    query_id = secrets.randbits(16)
    packet = (
        struct.pack("!HHHHHH", query_id, 0x0100, 1, 0, 0, 0)
        + qname
        + struct.pack("!HH", query_type, 1)
    )

    ip = ipaddress.ip_address(nameserver)
    family = socket.AF_INET6 if ip.version == 6 else socket.AF_INET
    endpoint: Any = (nameserver, 53, 0, 0) if ip.version == 6 else (nameserver, 53)

    with socket.socket(family, socket.SOCK_DGRAM) as sock:
        sock.settimeout(timeout)
        sock.sendto(packet, endpoint)
        response, _ = sock.recvfrom(65535)

    rcode, truncated, addresses = parse_dns_response(response, query_id)
    if not truncated:
        return rcode, addresses

    with socket.socket(family, socket.SOCK_STREAM) as sock:
        sock.settimeout(timeout)
        sock.connect(endpoint)
        sock.sendall(struct.pack("!H", len(packet)) + packet)
        size = struct.unpack("!H", receive_exact(sock, 2))[0]
        response = receive_exact(sock, size)
    rcode, _, addresses = parse_dns_response(response, query_id)
    return rcode, addresses


def lookup_dns(host: str, timeout: float) -> dict[str, Any]:
    try:
        address = str(ipaddress.ip_address(host))
        return {"status": "resolved", "addresses": [address]}
    except ValueError:
        pass

    servers = resolver_addresses()
    if not servers:
        return {"status": "unknown", "reason": "no resolver in /etc/resolv.conf"}

    deadline = time.monotonic() + timeout
    saw_noerror = False
    errors: list[str] = []

    for query_type in (1, 28):
        for server in servers:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return {"status": "unknown", "reason": "DNS timeout"}
            try:
                rcode, addresses = one_dns_query(
                    server, host, query_type, max(0.05, remaining)
                )
                if rcode == 3:
                    return {"status": "nxdomain", "addresses": []}
                if rcode == 0:
                    saw_noerror = True
                    if addresses:
                        return {"status": "resolved", "addresses": addresses}
                else:
                    errors.append(f"rcode={rcode}")
            except (OSError, ValueError) as exc:
                errors.append(type(exc).__name__)

    if saw_noerror:
        return {"status": "no_address", "addresses": []}
    reason = "DNS lookup failed"
    if errors:
        reason += f" ({', '.join(errors[:3])})"
    return {"status": "unknown", "reason": reason}


def retry_after_seconds(headers: Any) -> float:
    value = headers.get("Retry-After") if headers else None
    if not value:
        return 2.0
    try:
        return min(30.0, max(1.0, float(value)))
    except ValueError:
        try:
            when = email.utils.parsedate_to_datetime(value)
            now = dt.datetime.now(dt.timezone.utc)
            if when.tzinfo is None:
                when = when.replace(tzinfo=dt.timezone.utc)
            return min(30.0, max(1.0, (when - now).total_seconds()))
        except (TypeError, ValueError, OverflowError):
            return 2.0


def parse_rdap_date(value: str) -> dt.datetime | None:
    try:
        parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=dt.timezone.utc)
        return parsed.astimezone(dt.timezone.utc)
    except (TypeError, ValueError):
        return None


def lookup_rdap(
    domain: str,
    timeout: float,
    retries: int,
    limiter: RateLimiter,
    budget: NetworkBudget,
) -> dict[str, Any]:
    url = "https://rdap.org/domain/" + urllib.parse.quote(domain, safe="")
    headers = {
        "Accept": "application/rdap+json, application/json",
        "User-Agent": "PATANYX-fp-review/1.0 (read-only human-review tool)",
    }

    for attempt in range(retries + 1):
        if attempt and not budget.reserve():
            return {"status": "unknown", "reason": "network budget exhausted"}

        limiter.acquire()
        try:
            request = urllib.request.Request(url, headers=headers)
            with urllib.request.urlopen(request, timeout=timeout) as response:
                raw = response.read(2_000_001)
                if len(raw) > 2_000_000:
                    return {"status": "unknown", "reason": "oversized RDAP response"}
                document = json.loads(raw.decode("utf-8"))
        except urllib.error.HTTPError as exc:
            if exc.code == 404:
                return {"status": "not_found", "domain": domain}
            if exc.code == 429:
                delay = retry_after_seconds(exc.headers) + random.random()
                limiter.defer(delay)
                if attempt < retries:
                    continue
                return {"status": "rate_limited", "reason": "RDAP HTTP 429"}
            return {"status": "unknown", "reason": f"RDAP HTTP {exc.code}"}
        except (
            urllib.error.URLError,
            TimeoutError,
            OSError,
            ValueError,
            json.JSONDecodeError,
        ) as exc:
            return {
                "status": "unknown",
                "reason": f"RDAP {type(exc).__name__}",
            }

        dates: list[dt.datetime] = []
        for event in document.get("events", []):
            if not isinstance(event, dict):
                continue
            action = str(event.get("eventAction", "")).lower()
            if action not in {"registration", "registered"}:
                continue
            parsed = parse_rdap_date(str(event.get("eventDate", "")))
            if parsed:
                dates.append(parsed)

        if not dates:
            return {
                "status": "found",
                "domain": domain,
                "registration_date": None,
            }

        registration = min(dates)
        return {
            "status": "found",
            "domain": domain,
            "registration_date": registration.isoformat(),
        }

    return {"status": "unknown", "reason": "RDAP retry exhaustion"}


def certificate_name(parts: Any, key: str) -> str | None:
    for group in parts or ():
        for name, value in group:
            if name == key:
                return str(value)
    return None


def lookup_tls(host: str, addresses: list[str], timeout: float) -> dict[str, Any]:
    if not addresses:
        return {"status": "unknown", "reason": "no resolved address"}

    # Prefer IPv4 only to avoid treating local IPv6 reachability as a property
    # of the host. Exactly one address is contacted, once.
    ordered = sorted(
        addresses,
        key=lambda value: 0 if ipaddress.ip_address(value).version == 4 else 1,
    )
    address = ordered[0]

    # NEVER DIAL A NON-GLOBAL ADDRESS. The address comes from resolving a host
    # supplied by a third-party feed, so the destination is attacker-choosable:
    # an entry resolving to 127.0.0.1, 10.x or 169.254.169.254 would have the
    # build host open a connection to its own network, or to a cloud metadata
    # endpoint, on the say-so of a downloaded list. Only a TLS handshake is
    # ever sent, so the reachable damage is small, but the fix is one check and
    # the alternative is trusting a list this tool exists to be sceptical of.
    if not ipaddress.ip_address(address).is_global:
        return {"status": "unknown", "reason": "non-global address"}
    ip = ipaddress.ip_address(address)
    family = socket.AF_INET if ip.version == 4 else socket.AF_INET6
    endpoint: Any = (address, 443) if ip.version == 4 else (address, 443, 0, 0)

    raw_sock: socket.socket | None = socket.socket(family, socket.SOCK_STREAM)
    raw_sock.settimeout(timeout)
    context = ssl.create_default_context()

    try:
        raw_sock.connect(endpoint)
        tls_sock = context.wrap_socket(raw_sock, server_hostname=host)
        raw_sock = None  # Ownership moved to tls_sock.
        with tls_sock:
            tls_sock.settimeout(timeout)
            certificate = tls_sock.getpeercert()
            cipher = tls_sock.cipher()
            protocol = tls_sock.version()
    except ssl.SSLCertVerificationError as exc:
        return {
            "status": "invalid_certificate",
            "reason": str(exc)[:180],
        }
    except (ssl.SSLError, OSError, TimeoutError) as exc:
        return {
            "status": "unknown",
            "reason": f"TLS {type(exc).__name__}",
        }
    finally:
        if raw_sock is not None:
            raw_sock.close()

    issuer = certificate_name(certificate.get("issuer"), "organizationName")
    if not issuer:
        issuer = certificate_name(certificate.get("issuer"), "commonName")
    organization = certificate_name(certificate.get("subject"), "organizationName")

    not_before = certificate.get("notBefore")
    not_after = certificate.get("notAfter")
    span_days: float | None = None
    if not_before and not_after:
        try:
            span_days = (
                ssl.cert_time_to_seconds(not_after)
                - ssl.cert_time_to_seconds(not_before)
            ) / 86400.0
        except (ValueError, OverflowError):
            pass

    return {
        "status": "valid",
        "issuer": issuer,
        "subject_organization": organization,
        "validity_days": round(span_days, 1) if span_days is not None else None,
        "protocol": protocol,
        "cipher": cipher[0] if cipher else None,
    }


def tranco_points(rank: int) -> int:
    # Popularity within this band is an impact gradient, not an innocence vote.
    return 30 - round((rank - 10001) * 15 / 89999)


def offline_score(
    host: str,
    shape: dict[str, Any],
    rank: int | None,
    sources: set[str],
    source_complete: bool,
) -> int:
    score = tranco_points(rank) if rank and 10001 <= rank <= 100000 else 0
    if shape["kind"] == "public_suffix":
        score += 45
    elif shape["kind"] == "service_apex":
        score += 18
    elif shape["kind"] == "subdomain" and shape["subdomain_depth"] == 1:
        score += 3

    if source_complete:
        if len(sources) == 1:
            score += 18
            if sources == {"PhishDestroy"}:
                score += 8
        elif len(sources) == 2:
            score -= 6
        elif len(sources) == 3:
            score -= 12
    return score


def years_old(registration_date: str | None) -> float | None:
    if not registration_date:
        return None
    registered = parse_rdap_date(registration_date)
    if not registered:
        return None
    return max(
        0.0,
        (dt.datetime.now(dt.timezone.utc) - registered).total_seconds()
        / (365.2425 * 86400),
    )


def score_candidate(record: dict[str, Any], source_complete: bool) -> None:
    score = 0
    reasons: list[str] = []

    rank = record["tranco_rank"]
    if rank is not None and 10001 <= rank <= 100000:
        points = tranco_points(rank)
        score += points
        covered = record["tranco_covered_host"]
        relation = "exact host" if covered == record["host"] else f"covered descendant {covered}"
        reasons.append(
            f"+{points} Tranco #{rank} ({relation}; impact, not innocence)"
        )

    kind = record["shape"]["kind"]
    if kind == "public_suffix":
        score += 45
        reasons.append("+45 public-suffix-scale blast radius")
    elif kind == "service_apex":
        score += 18
        reasons.append("+18 service/registrable apex blast radius")
    elif kind == "subdomain" and record["shape"]["subdomain_depth"] == 1:
        score += 3
        reasons.append("+3 shallow subdomain blast radius")

    sources = set(record["sources"])
    if source_complete:
        if len(sources) == 1:
            score += 18
            reasons.append("+18 single-source allegation")
            if sources == {"PhishDestroy"}:
                score += 8
                reasons.append("+8 PhishDestroy-only report")
        elif len(sources) == 2:
            score -= 6
            reasons.append("-6 two exact-host feed reports")
        elif len(sources) == 3:
            score -= 12
            reasons.append("-12 three exact-host feed reports")
    else:
        reasons.append("source corroboration incomplete and unscored")

    dns = record["dns"]
    if dns.get("status") == "resolved":
        score += 3
        reasons.append("+3 currently resolves (current-impact signal)")
    elif dns.get("status") == "nxdomain":
        score -= 8
        reasons.append("-8 NXDOMAIN (lower current impact; not exoneration)")
    elif dns.get("status") == "no_address":
        score -= 5
        reasons.append("-5 no A/AAAA address")

    rdap = record["rdap"]
    age = years_old(rdap.get("registration_date"))
    record["rdap_age_years"] = round(age, 2) if age is not None else None
    if age is not None:
        if age >= 15:
            points = 38
        elif age >= 10:
            points = 34
        elif age >= 5:
            points = 24
        elif age >= 2:
            points = 12
        elif age >= 1:
            points = 5
        else:
            points = 0
        if points:
            score += points
            reasons.append(f"+{points} exact-domain registration age {age:.1f}y")

    tls = record["tls"]
    if tls.get("status") == "valid":
        organization = tls.get("subject_organization")
        span = tls.get("validity_days")
        if organization:
            points = 10 if span is not None and span >= 300 else 6
            score += points
            reasons.append(
                f"+{points} valid exact-host TLS with subject organization"
            )
        elif span is not None and span >= 300:
            # Validity alone is easy to game and says nothing about content, so
            # it receives only a token weight.
            score += 2
            reasons.append("+2 valid exact-host TLS lasting at least 300 days")

    if not reasons:
        reasons.append(
            "no positive signal fired; retained because unknown lookups never exclude it"
        )

    record["score"] = score
    record["rationale"] = "; ".join(reasons)


def shorten(value: Any, width: int) -> str:
    text = "-" if value is None else str(value)
    text = " ".join(text.split())
    if len(text) <= width:
        return text
    return text[: max(1, width - 1)] + "…"


def print_human(meta: dict[str, Any], records: list[dict[str, Any]]) -> None:
    print("PATANYX false-positive human-review queue")
    print("HIGH SCORE = WORTH A HUMAN LOOK; IT DOES NOT MEAN SAFE OR UNBLOCK.")
    print(
        f"window offset={meta['offset']} limit={meta['limit']} "
        f"selected={meta['selected']} network={meta['network_used']}/"
        f"{meta['network_budget']} cache={meta['cache_path']}"
    )
    print(
        f"feeds loaded={meta['feeds_loaded']}; "
        f"corroboration_complete={str(meta['corroboration_complete']).lower()}"
    )
    if meta["skipped_top_10000"]:
        print(
            f"skipped {meta['skipped_top_10000']} Tranco-top-10k entries "
            "(handled by the build tripwire)"
        )
    print()

    if not records:
        print("No candidates in this selection window.")
        return

    host_width = min(80, max(12, max(len(r["host"]) for r in records)))
    header = (
        f"{'SCORE':>5}  {'HOST':<{host_width}}  {'TRANCO':>7}  "
        f"{'SOURCES':<22}  {'SHAPE':<15}  {'DNS':<10}  "
        f"{'RDAP AGE':<10}  {'TLS':<24}"
    )
    print(header)
    print("-" * len(header))

    aliases = {
        "Phishing.Database": "PDB",
        "phishunt.io": "Hunt",
        "PhishDestroy": "Destroy",
    }
    for record in records:
        source_names = ",".join(aliases.get(s, s) for s in record["sources"]) or "-"
        if not meta["corroboration_complete"]:
            source_names += " (partial)"
        age = record["rdap_age_years"]
        age_text = f"{age:.1f}y exact" if age is not None else "-"
        tls = record["tls"]
        if tls.get("status") == "valid":
            tls_text = (
                f"{tls.get('issuer') or 'valid CA'}, "
                f"{tls.get('validity_days') or '?'}d"
            )
        else:
            tls_text = tls.get("status", "unknown")
        rank = record["tranco_rank"]

        print(
            f"{record['score']:>5}  "
            f"{record['host']:<{host_width}}  "
            f"{rank if rank is not None else '-':>7}  "
            f"{shorten(source_names, 22):<22}  "
            f"{shorten(record['shape']['kind'], 15):<15}  "
            f"{shorten(record['dns'].get('status'), 10):<10}  "
            f"{age_text:<10}  "
            f"{shorten(tls_text, 24):<24}"
        )
        print(f"       rationale: {record['rationale']}")


def find_repo(explicit: str | None) -> Path:
    if explicit:
        return Path(explicit).resolve()
    probes = [Path.cwd(), *Path.cwd().parents]
    try:
        script_dir = Path(__file__).resolve().parent
        probes.extend([script_dir, *script_dir.parents])
    except NameError:
        pass
    for probe in probes:
        if (probe / "crates/app/src/blocklist.txt").is_file():
            return probe
    return Path.cwd()


def parse_feed_arguments(values: list[str]) -> dict[str, Path]:
    result: dict[str, Path] = {}
    for value in values:
        if "=" not in value:
            raise ValueError("--feed must be NAME=PATH")
        label, path_text = value.split("=", 1)
        canonical = canonical_feed_name(label)
        if canonical is None:
            raise ValueError(
                f"unrecognized feed name {label!r}; use "
                "Phishing.Database, phishunt.io, or PhishDestroy"
            )
        result[canonical] = Path(path_text)
    return result


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Rank PATANYX blocklist entries for human false-positive review. "
            "High scores are review priority, never an unblock verdict."
        )
    )
    parser.add_argument("--repo", help="PATANYX repository root")
    parser.add_argument("--blocklist", type=Path)
    parser.add_argument("--psl", type=Path)
    parser.add_argument("--tranco", type=Path)
    parser.add_argument("--allow", type=Path)
    parser.add_argument("--confirm", type=Path)
    parser.add_argument(
        "--state-dir",
        type=Path,
        default=Path("/var/lib/patanyx-blocklist"),
        help="directory searched for current feed snapshots",
    )
    parser.add_argument(
        "--feed",
        action="append",
        default=[],
        metavar="NAME=PATH",
        help=(
            "feed snapshot; repeat for Phishing.Database, phishunt.io, and "
            "PhishDestroy. Explicit entries override auto-discovery"
        ),
    )
    parser.add_argument("--limit", type=int, default=50)
    parser.add_argument("--offset", type=int, default=0)
    parser.add_argument(
        "--network-budget",
        type=int,
        default=200,
        help="maximum uncached DNS, RDAP, TLS, and RDAP-retry operations",
    )
    parser.add_argument("--workers", type=int, default=12)
    parser.add_argument("--dns-timeout", type=float, default=4.0)
    parser.add_argument("--tls-timeout", type=float, default=5.0)
    parser.add_argument("--rdap-timeout", type=float, default=10.0)
    parser.add_argument(
        "--rdap-interval",
        type=float,
        default=1.0,
        help="minimum seconds between RDAP requests",
    )
    parser.add_argument("--rdap-retries", type=int, default=2)
    parser.add_argument(
        "--cache",
        type=Path,
        help="network-result cache path (default: user cache directory)",
    )
    parser.add_argument(
        "--cache-ttl-hours",
        type=float,
        default=168.0,
        help="successful-result TTL; transient failures use at most six hours",
    )
    parser.add_argument("--json", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.limit < 0 or args.offset < 0:
        parser.error("--limit and --offset must be non-negative")
    if args.workers < 1:
        parser.error("--workers must be at least 1")
    if min(args.dns_timeout, args.tls_timeout, args.rdap_timeout) <= 0:
        parser.error("timeouts must be positive")

    repo = find_repo(args.repo)
    blocklist_path = args.blocklist or repo / "crates/app/src/blocklist.txt"
    psl_path = args.psl or repo / "crates/app/src/public_suffix_list.txt"
    tranco_path = (
        args.tranco
        or Path("/var/lib/patanyx-blocklist/tranco-top100k.txt")
    )
    allow_path = args.allow or repo / "scripts/blocklist-allow.txt"
    confirm_path = args.confirm or repo / "scripts/blocklist-confirm.txt"

    try:
        blocklist = read_simple_host_file(blocklist_path, required=True)
    except OSError as exc:
        parser.error(f"cannot read blocklist {blocklist_path}: {exc}")
    blockset = set(blocklist)

    try:
        psl = PublicSuffixList(psl_path)
    except OSError as exc:
        parser.error(f"cannot read PSL {psl_path}: {exc}")

    adjudicated = set(read_simple_host_file(allow_path))
    adjudicated.update(read_simple_host_file(confirm_path))

    covered_rank, covered_name, exact_rank = load_tranco_coverage(
        tranco_path, blockset
    )

    feeds = discover_feeds(args.state_dir)
    try:
        feeds.update(parse_feed_arguments(args.feed))
    except ValueError as exc:
        parser.error(str(exc))

    sources_by_host: dict[str, set[str]] = {}
    loaded_feeds: dict[str, str] = {}
    for feed_name in EXPECTED_FEEDS:
        path = feeds.get(feed_name)
        if path is None:
            continue
        if not path.is_file():
            warn(f"{feed_name} snapshot not found at {path}")
            continue
        loaded_feeds[feed_name] = str(path)
        for host in feed_hosts(path, blockset):
            sources_by_host.setdefault(host, set()).add(feed_name)

    source_complete = all(name in loaded_feeds for name in EXPECTED_FEEDS)
    if not source_complete:
        missing = [name for name in EXPECTED_FEEDS if name not in loaded_feeds]
        warn(
            "corroboration is incomplete and will not affect scores; missing: "
            + ", ".join(missing)
            + ". Supply snapshots with --feed NAME=PATH."
        )

    candidates: list[dict[str, Any]] = []
    skipped_top = 0
    for host in blocklist:
        if host in adjudicated:
            continue

        rank = covered_rank.get(host)
        if rank is not None and rank <= 10000:
            skipped_top += 1
            continue

        shape = classify_shape(host, psl)
        sources = sources_by_host.get(host, set())
        preliminary = offline_score(
            host, shape, rank, sources, source_complete
        )

        # The explicit 10k-100k gap comes first. A stable hash breaks ties
        # without alphabetical/TLD bias and makes --offset resumable.
        tier = 0 if rank is not None and rank <= 100000 else 1
        stable = hashlib.sha256(host.encode("ascii")).hexdigest()
        candidates.append(
            {
                "host": host,
                "shape": shape,
                "sources": sorted(sources),
                "tranco_rank": rank,
                "tranco_exact_rank": exact_rank.get(host),
                "tranco_covered_host": covered_name.get(host),
                "offline_score": preliminary,
                "_sort": (tier, -preliminary, stable),
            }
        )

    candidates.sort(key=lambda item: item["_sort"])
    selected = candidates[args.offset:args.offset + args.limit]
    for index, record in enumerate(selected, start=args.offset):
        record["selection_index"] = index
        record.pop("_sort", None)

    default_cache_root = Path(
        os.environ.get(
            "XDG_CACHE_HOME",
            str(Path.home() / ".cache"),
        )
    )
    cache_path = args.cache or default_cache_root / "patanyx/fp-review.json"
    protected = [
        blocklist_path,
        allow_path,
        confirm_path,
        psl_path,
        tranco_path,
        *feeds.values(),
    ]
    cache = ResultCache(
        cache_path,
        max(0.0, args.cache_ttl_hours * 3600),
        protected,
    )
    budget = NetworkBudget(args.network_budget)
    limiter = RateLimiter(args.rdap_interval)

    dns_jobs: list[tuple[str, str]] = []
    rdap_jobs: list[tuple[str, str]] = []

    for record in selected:
        host = record["host"]
        cached_dns = cache.get(f"dns|{host}")
        record["dns"] = cached_dns or dict(UNKNOWN)

        rdap_domain = record["shape"]["rdap_domain"]
        # RDAP is queried only when it describes the exact listed registered
        # domain. Querying example.com for evil.example.com would import the
        # parent's age into a subdomain review, recreating the lookalike mistake
        # this tool is intended to prevent.
        if rdap_domain == host:
            cached_rdap = cache.get(f"rdap|{rdap_domain}")
            record["rdap"] = cached_rdap or dict(UNKNOWN)
        else:
            record["rdap"] = {
                "status": "not_queried",
                "reason": (
                    "listed host is not the exact ICANN registrable domain; "
                    "parent age is deliberately not attributed"
                ),
                "domain": rdap_domain,
            }

        cached_tls = cache.get(f"tls|{host}")
        record["tls"] = cached_tls or dict(UNKNOWN)

    # Reserve strongest exact-domain evidence first, then DNS. Tasks are
    # submitted DNS-first so DNS and serialized polite RDAP can overlap.
    for record in selected:
        host = record["host"]
        rdap_domain = record["shape"]["rdap_domain"]
        if (
            rdap_domain == host
            and record["rdap"].get("reason") == "not looked up"
            and budget.reserve()
        ):
            rdap_jobs.append((host, rdap_domain))

    for record in selected:
        host = record["host"]
        if (
            record["dns"].get("reason") == "not looked up"
            and budget.reserve()
        ):
            dns_jobs.append((host, host))

    by_host = {record["host"]: record for record in selected}
    with concurrent.futures.ThreadPoolExecutor(
        max_workers=args.workers
    ) as executor:
        future_map: dict[concurrent.futures.Future[dict[str, Any]], tuple[str, str]] = {}

        for host, _ in dns_jobs:
            future = executor.submit(lookup_dns, host, args.dns_timeout)
            future_map[future] = ("dns", host)

        for host, domain in rdap_jobs:
            future = executor.submit(
                lookup_rdap,
                domain,
                args.rdap_timeout,
                max(0, args.rdap_retries),
                limiter,
                budget,
            )
            future_map[future] = ("rdap", host)

        for future in concurrent.futures.as_completed(future_map):
            kind, host = future_map[future]
            try:
                value = future.result()
            except Exception as exc:  # A signal must never crash the report.
                value = {
                    "status": "unknown",
                    "reason": f"{kind} worker {type(exc).__name__}",
                }
            by_host[host][kind] = value
            key_name = (
                by_host[host]["shape"]["rdap_domain"]
                if kind == "rdap"
                else host
            )
            cache.set(f"{kind}|{key_name}", value)

    # TLS is contacted only after DNS says the exact host resolves, avoiding
    # needless connections to NXDOMAIN/inactive entries.
    tls_jobs: list[str] = []
    for record in selected:
        host = record["host"]
        if (
            record["tls"].get("reason") == "not looked up"
            and record["dns"].get("status") == "resolved"
            and budget.reserve()
        ):
            tls_jobs.append(host)

    with concurrent.futures.ThreadPoolExecutor(
        max_workers=args.workers
    ) as executor:
        futures = {
            executor.submit(
                lookup_tls,
                host,
                list(by_host[host]["dns"].get("addresses", [])),
                args.tls_timeout,
            ): host
            for host in tls_jobs
        }
        for future in concurrent.futures.as_completed(futures):
            host = futures[future]
            try:
                value = future.result()
            except Exception as exc:
                value = {
                    "status": "unknown",
                    "reason": f"TLS worker {type(exc).__name__}",
                }
            by_host[host]["tls"] = value
            cache.set(f"tls|{host}", value)

    cache.save()

    for record in selected:
        score_candidate(record, source_complete)
    selected.sort(key=lambda item: (-item["score"], item["selection_index"]))

    generated = dt.datetime.now(dt.timezone.utc).isoformat()
    meta = {
        "generated_at": generated,
        "meaning": (
            "High score means worth human review; it never means safe or unblock."
        ),
        "blocklist": str(blocklist_path),
        "blocklist_hosts": len(blocklist),
        "adjudicated_hosts_skipped": len(blockset & adjudicated),
        "skipped_top_10000": skipped_top,
        "eligible_candidates": len(candidates),
        "offset": args.offset,
        "limit": args.limit,
        "selected": len(selected),
        "network_budget": max(0, args.network_budget),
        "network_used": budget.used,
        "cache_path": str(cache_path),
        "feeds_loaded": loaded_feeds,
        "corroboration_complete": source_complete,
        "ranking_scope": "selected window only",
    }

    if args.json:
        json.dump(
            {"meta": meta, "candidates": selected},
            sys.stdout,
            indent=2,
            sort_keys=True,
        )
        print()
    else:
        print_human(meta, selected)

    # Candidates are findings for review, not a build failure.
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except BrokenPipeError:
        # Piping the report through head(1) is not an audit failure.
        raise SystemExit(0)
