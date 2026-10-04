"""Scope parsing, CIDR expansion and scope enforcement.

This module is the single authority on what may be scanned.  Every target list
that reaches an external tool is produced by :meth:`Scope.enforce` or
:meth:`Scope.write_targets`; no stage constructs target arguments on its own.

Design notes
------------
* The in-scope set is *explicit*: the scope file is expanded once into a
  ``frozenset`` of :class:`ipaddress` objects.  Membership tests run against
  that same set, so the set the tools see and the set enforcement checks can
  never drift apart.
* Hostnames are rejected.  A name cannot be shown to be in scope without DNS
  resolution, and the scope file does not authorise resolving or scanning
  whatever a name happens to point at today.
* Anything a parser hands back that is not in the set is dropped and logged
  (defence against a tool reporting a host we never asked about).  Anything
  *our own code* tries to scan out of scope raises :class:`ScopeViolation`.
"""

from __future__ import annotations

import ipaddress
import logging
from collections.abc import Iterable, Iterator, Sequence
from dataclasses import dataclass
from pathlib import Path

from netrecon.core.jsonio import ARTIFACT_MODE

log = logging.getLogger(__name__)

IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address
IPNetwork = ipaddress.IPv4Network | ipaddress.IPv6Network

#: Hard ceiling on the expanded scope, so a stray ``/8`` fails loudly at parse
#: time instead of exhausting memory half way through a run.
DEFAULT_MAX_HOSTS = 65_536


class ScopeError(Exception):
    """Base class for scope problems."""


class ScopeParseError(ScopeError):
    """The scope file could not be parsed into an in-scope set."""


class ScopeViolation(ScopeError):
    """Code attempted to scan an address outside the in-scope set."""


@dataclass(frozen=True)
class ScopeEntry:
    """One accepted line of the scope file."""

    lineno: int
    raw: str
    kind: str  # "ip" | "cidr" | "range"
    addresses: tuple[IPAddress, ...]

    @property
    def count(self) -> int:
        return len(self.addresses)


@dataclass(frozen=True)
class ScopeReject:
    """One rejected line of the scope file, kept for the run report."""

    lineno: int
    raw: str
    reason: str


@dataclass(frozen=True)
class EnforcementResult:
    """Outcome of filtering candidate addresses against the scope."""

    allowed: tuple[IPAddress, ...]
    rejected: tuple[tuple[str, str], ...] = ()  # (candidate, reason)

    @property
    def allowed_str(self) -> tuple[str, ...]:
        return tuple(str(a) for a in self.allowed)

    def __bool__(self) -> bool:  # pragma: no cover - convenience only
        return bool(self.allowed)


def _parse_address(token: str) -> IPAddress:
    return ipaddress.ip_address(token)


def _expand_network(net: IPNetwork, include_network_broadcast: bool) -> list[IPAddress]:
    """Expand a network to the addresses we are willing to probe.

    For a point-to-point or single-host prefix every address is usable.  For
    wider IPv4 prefixes the network and broadcast addresses are skipped by
    default, matching what ``nmap`` and ``masscan`` treat as hosts.  IPv6
    prefixes are expanded in full - there is no broadcast address to skip.
    """
    if net.version == 6:
        # IPv6 has no broadcast address, and ::0 is a valid anycast target, so
        # every address in the prefix is scannable.
        return list(net)
    host_bits = net.max_prefixlen - net.prefixlen
    if host_bits <= 1 or include_network_broadcast:
        return list(net)
    return list(net.hosts())


def _expand_range(start: IPAddress, end: IPAddress) -> list[IPAddress]:
    if start.version != end.version:
        raise ScopeParseError("range endpoints must be the same IP version")
    if int(end) < int(start):
        raise ScopeParseError("range end is lower than range start")
    cls = ipaddress.IPv4Address if start.version == 4 else ipaddress.IPv6Address
    return [cls(value) for value in range(int(start), int(end) + 1)]


def _sort_key(addr: IPAddress) -> tuple[int, int]:
    return (addr.version, int(addr))


class Scope:
    """An explicit, immutable set of in-scope addresses."""

    def __init__(
        self,
        addresses: Iterable[IPAddress],
        *,
        entries: Sequence[ScopeEntry] = (),
        rejects: Sequence[ScopeReject] = (),
        source: str | None = None,
    ) -> None:
        self._addresses: frozenset[IPAddress] = frozenset(addresses)
        self._ordered: tuple[IPAddress, ...] = tuple(sorted(self._addresses, key=_sort_key))
        self.entries: tuple[ScopeEntry, ...] = tuple(entries)
        self.rejects: tuple[ScopeReject, ...] = tuple(rejects)
        self.source = source

    # -- construction ----------------------------------------------------

    @classmethod
    def from_lines(
        cls,
        lines: Iterable[str],
        *,
        max_hosts: int = DEFAULT_MAX_HOSTS,
        include_network_broadcast: bool = False,
        source: str | None = None,
    ) -> Scope:
        """Parse and expand scope lines into an explicit address set.

        Accepted forms: ``IP``, ``CIDR``, ``START-END``.  Comments start with
        ``#``.  Every other line is rejected with a reason.
        """
        addresses: set[IPAddress] = set()
        entries: list[ScopeEntry] = []
        rejects: list[ScopeReject] = []

        for lineno, raw_line in enumerate(lines, start=1):
            raw = raw_line.split("#", 1)[0].strip()
            if not raw:
                continue
            try:
                kind, expanded = cls._parse_entry(raw, include_network_broadcast)
            except ScopeParseError as exc:
                rejects.append(ScopeReject(lineno, raw, str(exc)))
                continue
            except ValueError as exc:
                rejects.append(ScopeReject(lineno, raw, f"not an IP, CIDR or range: {exc}"))
                continue

            if not expanded:
                rejects.append(ScopeReject(lineno, raw, "expanded to zero usable hosts"))
                continue

            addresses.update(expanded)
            entries.append(ScopeEntry(lineno, raw, kind, tuple(expanded)))

            if len(addresses) > max_hosts:
                raise ScopeParseError(
                    f"scope expands to more than {max_hosts} hosts "
                    f"(reached at line {lineno}: {raw!r}); narrow the scope or raise "
                    "scope.max_hosts in the config"
                )

        if not addresses:
            detail = "; ".join(f"line {r.lineno}: {r.reason}" for r in rejects[:5])
            raise ScopeParseError(
                "scope file produced no in-scope addresses" + (f" ({detail})" if detail else "")
            )

        return cls(addresses, entries=entries, rejects=rejects, source=source)

    @classmethod
    def from_file(
        cls,
        path: str | Path,
        *,
        max_hosts: int = DEFAULT_MAX_HOSTS,
        include_network_broadcast: bool = False,
    ) -> Scope:
        path = Path(path)
        if not path.is_file():
            raise ScopeParseError(f"scope file not found: {path}")
        with path.open("r", encoding="utf-8", errors="replace") as handle:
            return cls.from_lines(
                handle,
                max_hosts=max_hosts,
                include_network_broadcast=include_network_broadcast,
                source=str(path),
            )

    @staticmethod
    def _parse_entry(
        raw: str, include_network_broadcast: bool
    ) -> tuple[str, list[IPAddress]]:
        if _looks_like_hostname(raw):
            raise ScopeParseError(
                "hostnames are not accepted; list the authorised IPs or CIDRs instead"
            )

        if "-" in raw:
            start_token, _, end_token = raw.partition("-")
            start = _parse_address(start_token.strip())
            end = _parse_address(end_token.strip())
            return "range", _expand_range(start, end)

        if "/" in raw:
            net = ipaddress.ip_network(raw, strict=False)
            return "cidr", _expand_network(net, include_network_broadcast)

        return "ip", [_parse_address(raw)]

    # -- membership ------------------------------------------------------

    def __contains__(self, candidate: object) -> bool:
        try:
            addr = candidate if isinstance(candidate, (ipaddress.IPv4Address, ipaddress.IPv6Address)) else _parse_address(str(candidate))
        except ValueError:
            return False
        return addr in self._addresses

    def __len__(self) -> int:
        return len(self._addresses)

    def __iter__(self) -> Iterator[IPAddress]:
        return iter(self._ordered)

    @property
    def addresses(self) -> tuple[IPAddress, ...]:
        """In-scope addresses, deterministically ordered."""
        return self._ordered

    # -- enforcement -----------------------------------------------------

    def enforce(self, candidates: Iterable[str | IPAddress]) -> EnforcementResult:
        """Filter *candidates* down to the in-scope set.

        Unparseable and out-of-scope candidates are returned in
        ``rejected`` rather than raising: this path handles data coming back
        from external tools, which we do not trust to stay inside scope.
        """
        allowed: list[IPAddress] = []
        rejected: list[tuple[str, str]] = []
        seen: set[IPAddress] = set()

        for candidate in candidates:
            text = str(candidate).strip()
            if not text:
                continue
            try:
                addr = _parse_address(text)
            except ValueError:
                rejected.append((text, "not a bare IP address"))
                continue
            if addr not in self._addresses:
                rejected.append((text, "outside the in-scope set"))
                continue
            if addr in seen:
                continue
            seen.add(addr)
            allowed.append(addr)

        if rejected:
            log.warning(
                "scope filter dropped %d candidate(s); first few: %s",
                len(rejected),
                ", ".join(f"{c} ({r})" for c, r in rejected[:5]),
            )

        return EnforcementResult(
            tuple(sorted(allowed, key=_sort_key)), tuple(rejected)
        )

    def enforce_strict(self, candidates: Iterable[str | IPAddress]) -> tuple[IPAddress, ...]:
        """Like :meth:`enforce`, but any rejection is a programming error.

        Used on paths where the candidates originate inside netrecon, where an
        out-of-scope address means a bug rather than untrusted input.
        """
        result = self.enforce(candidates)
        if result.rejected:
            preview = ", ".join(f"{c} ({r})" for c, r in result.rejected[:5])
            raise ScopeViolation(
                f"refusing to scan {len(result.rejected)} out-of-scope target(s): {preview}"
            )
        return result.allowed

    def write_targets(
        self, path: str | Path, candidates: Iterable[str | IPAddress] | None = None
    ) -> tuple[Path, int]:
        """Write an enforced target list for a tool to consume.

        This is the only supported way to hand targets to a subprocess.  When
        *candidates* is ``None`` the whole scope is written.
        """
        path = Path(path)
        addresses = (
            self.addresses
            if candidates is None
            else self.enforce_strict(candidates)
        )
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("".join(f"{addr}\n" for addr in addresses), encoding="utf-8")
        # The scope is the client's authorised address list, and this same
        # method writes the run's scope.txt snapshot.
        try:
            path.chmod(ARTIFACT_MODE)
        except OSError:  # noqa: S110 - a filesystem without modes is not fatal
            pass
        return path, len(addresses)

    # -- reporting -------------------------------------------------------

    def notable_addresses(self) -> dict[str, tuple[IPAddress, ...]]:
        """Group addresses a reviewer should look twice at before scanning."""
        buckets: dict[str, list[IPAddress]] = {
            "loopback": [],
            "link_local": [],
            "multicast": [],
            "unspecified": [],
            "public": [],
        }
        for addr in self._ordered:
            if addr.is_loopback:
                buckets["loopback"].append(addr)
            elif addr.is_link_local:
                buckets["link_local"].append(addr)
            elif addr.is_multicast:
                buckets["multicast"].append(addr)
            elif addr.is_unspecified:
                buckets["unspecified"].append(addr)
            elif addr.is_global:
                buckets["public"].append(addr)
        return {name: tuple(values) for name, values in buckets.items() if values}

    def summary(self) -> dict[str, object]:
        return {
            "source": self.source,
            "entries": len(self.entries),
            "rejected_lines": len(self.rejects),
            "total_hosts": len(self._addresses),
            "ipv4_hosts": sum(1 for a in self._ordered if a.version == 4),
            "ipv6_hosts": sum(1 for a in self._ordered if a.version == 6),
            "first": str(self._ordered[0]) if self._ordered else None,
            "last": str(self._ordered[-1]) if self._ordered else None,
            "notable": {k: len(v) for k, v in self.notable_addresses().items()},
        }

    def fingerprint(self) -> str:
        """Stable digest of the in-scope set, used to guard resume."""
        import hashlib

        digest = hashlib.sha256()
        for addr in self._ordered:
            digest.update(str(addr).encode("ascii"))
            digest.update(b"\n")
        return digest.hexdigest()


def _looks_like_hostname(raw: str) -> bool:
    """True when *raw* contains characters only a hostname would have."""
    stripped = raw.strip("[]")
    if ":" in stripped and "/" not in stripped:
        # Bare IPv6 literals contain colons; hostnames do not.
        try:
            ipaddress.ip_address(stripped)
            return False
        except ValueError:
            pass
    return any(ch.isalpha() and ch.lower() not in "abcdef" for ch in stripped)
