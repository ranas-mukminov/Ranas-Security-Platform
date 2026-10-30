"""Fail-closed authorization boundaries for the *offline* ScopeProof laboratory.

A scope declaration is NOT evidence of a legally enforceable authorization.
This module intentionally denies every non-loopback target/source in v0.1.
"""

from __future__ import annotations

import ipaddress
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit

_METHODS = frozenset({"synthetic_authz", "rbac_review"})
_LOCAL_HOSTS = frozenset({"localhost", "127.0.0.1", "::1"})
_LOCAL_IPV4 = ipaddress.ip_network("127.0.0.0/8")
_LOCAL_IPV6 = ipaddress.ip_network("::1/128")


class InvalidScope(ValueError):
    """The supplied scope file cannot be used safely."""


class ScopeDenied(PermissionError):
    """A requested action falls outside the declared offline scope."""


def _parse_instant(value: str) -> datetime:
    try:
        result = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (TypeError, ValueError, AttributeError) as exc:
        raise InvalidScope("timestamps must be ISO 8601 with timezone") from exc
    if result.tzinfo is None or result.utcoffset() is None:
        raise InvalidScope("scope timestamps must include a timezone")
    return result.astimezone(timezone.utc)


def _strings(value: object, field: str) -> tuple[str, ...]:
    if not isinstance(value, list) or not value or not all(
        isinstance(item, str) and item.strip() for item in value
    ):
        raise InvalidScope(f"{field} must be a nonempty list of strings")
    return tuple(value)


@dataclass(frozen=True)
class ScopePolicy:
    engagement_id: str
    authorization_reference: str
    lab_only: bool
    target_hosts: tuple[str, ...]
    source_cidrs: tuple[str, ...]
    ports: tuple[int, ...]
    methods: tuple[str, ...]
    starts_at: datetime
    ends_at: datetime
    max_actions: int
    stopped: bool = False

    @classmethod
    def from_dict(cls, raw: dict[str, object]) -> ScopePolicy:
        if not isinstance(raw, dict):
            raise InvalidScope("scope must be a JSON object")
        allowed_fields = {
            "engagement_id", "authorization_reference", "lab_only", "target_hosts",
            "source_cidrs", "ports", "methods", "starts_at", "ends_at",
            "max_actions", "stopped",
        }
        extra = set(raw) - allowed_fields
        if extra:
            raise InvalidScope(f"unknown scope keys: {', '.join(sorted(extra))}")
        label = raw.get("engagement_id")
        authorization = raw.get("authorization_reference")
        if not isinstance(label, str) or not label.strip():
            raise InvalidScope("engagement_id is required")
        if not isinstance(authorization, str) or not authorization.strip():
            raise InvalidScope("authorization_reference is required")
        if raw.get("lab_only") is not True:
            raise InvalidScope("v0.1 requires lab_only=true; live target testing is unsupported")
        if type(raw.get("stopped", False)) is not bool:
            raise InvalidScope("stopped must be a boolean")

        hosts = _strings(raw.get("target_hosts"), "target_hosts")
        if any(host not in _LOCAL_HOSTS for host in hosts):
            raise InvalidScope("all targets must be exact loopback hosts in v0.1")

        networks = _strings(raw.get("source_cidrs"), "source_cidrs")
        for entry in networks:
            try:
                network = ipaddress.ip_network(entry, strict=True)
            except ValueError as exc:
                raise InvalidScope(f"invalid source CIDR: {entry}") from exc
            permitted = _LOCAL_IPV4 if network.version == 4 else _LOCAL_IPV6
            if not network.subnet_of(permitted):
                raise InvalidScope("only loopback source CIDRs are permitted in v0.1")

        ports = raw.get("ports")
        if not isinstance(ports, list) or not ports or any(
            type(p) is not int or not 1 <= p <= 65535 for p in ports
        ):
            raise InvalidScope("ports must contain valid TCP port numbers")
        methods = _strings(raw.get("methods"), "methods")
        if any(m not in _METHODS for m in methods):
            raise InvalidScope("unsupported laboratory method")

        starts = _parse_instant(raw.get("starts_at"))
        ends = _parse_instant(raw.get("ends_at"))
        if starts >= ends:
            raise InvalidScope("scope end must occur after its start")
        limit = raw.get("max_actions")
        if type(limit) is not int or not 1 <= limit <= 100:
            raise InvalidScope("max_actions must be between 1 and 100")

        return cls(
            engagement_id=label, authorization_reference=authorization,
            lab_only=True, target_hosts=hosts, source_cidrs=networks,
            ports=tuple(ports), methods=methods, starts_at=starts,
            ends_at=ends, max_actions=limit, stopped=raw.get("stopped", False),
        )

    @classmethod
    def from_file(cls, path: str | Path) -> ScopePolicy:
        with Path(path).open(encoding="utf-8") as stream:
            return cls.from_dict(json.load(stream))

    def check(self, *, url: str, source_ip: str, method: str,
              now: datetime | None = None) -> ScopeDecision:
        """Inspect a proposed action; deliberately never accesses the network."""
        if self.stopped:
            return ScopeDecision(False, "emergency stop is set")
        when = now or datetime.now(timezone.utc)
        if when.tzinfo is None or when.utcoffset() is None:
            return ScopeDecision(False, "time is missing timezone")
        if not (self.starts_at <= when.astimezone(timezone.utc) <= self.ends_at):
            return ScopeDecision(False, "outside approved time window")
        if method not in self.methods:
            return ScopeDecision(False, "method not in scope")
        try:
            parsed = urlsplit(url)
            host = parsed.hostname
            port = parsed.port
            if (
                parsed.scheme not in ("http", "https") or parsed.username is not None
                or parsed.password is not None or parsed.fragment
                or host not in self.target_hosts or host not in _LOCAL_HOSTS
                or port not in self.ports
            ):
                return ScopeDecision(False, "target host, URL or port not in local scope")
        except (ValueError, AttributeError):
            return ScopeDecision(False, "invalid target URL")
        try:
            ip = ipaddress.ip_address(source_ip)
            if not ip.is_loopback or not any(
                ip in ipaddress.ip_network(cidr) for cidr in self.source_cidrs
            ):
                return ScopeDecision(False, "source IP not in local scope")
        except ValueError:
            return ScopeDecision(False, "invalid source IP")
        return ScopeDecision(True, "allowed: synthetic in-process lab only")


@dataclass(frozen=True)
class ScopeDecision:
    allowed: bool
    reason: str


class ScopeSession:
    """Rate/control gate for simulated actions; stops after the declared maximum."""

    def __init__(self, policy: ScopePolicy) -> None:
        self.policy = policy
        self.actions = 0
        self._stopped = False

    def emergency_stop(self) -> None:
        self._stopped = True

    def require(self, *, url: str, source_ip: str, method: str,
                now: datetime | None = None) -> None:
        if self._stopped:
            raise ScopeDenied("emergency stop requested")
        if self.actions >= self.policy.max_actions:
            raise ScopeDenied("maximum number of synthetic actions reached")
        result = self.policy.check(url=url, source_ip=source_ip, method=method, now=now)
        if not result.allowed:
            raise ScopeDenied(result.reason)
        self.actions += 1
