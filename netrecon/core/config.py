"""Configuration loading, validation and rate-limit enforcement."""

from __future__ import annotations

import copy
import logging
import re
from dataclasses import dataclass, field, fields
from pathlib import Path
from typing import Any

import yaml

log = logging.getLogger(__name__)

#: Absolute ceiling on masscan/naabu packet rate, enforced in code.  A config
#: file or CLI flag cannot exceed this; requests above it are clamped and
#: logged loudly.  The goal is that a typo cannot turn a recon run into a
#: denial of service against the client's network.
MASSCAN_RATE_HARD_MAX = 20_000

#: Rate above which the operator gets an explicit warning.
MASSCAN_RATE_WARN_THRESHOLD = 1_000

#: Absolute ceiling on nuclei requests per second.
NUCLEI_RATE_HARD_MAX = 300

#: Absolute ceiling on worker threads spawning subprocesses.
CONCURRENCY_HARD_MAX = 64

#: Absolute ceiling on web recon requests per second.  The web stage only
#: issues GETs, but a tight loop against one application is still load the
#: client did not agree to.
WEBRECON_RATE_HARD_MAX = 50

#: Rate above which the operator gets an explicit warning.
WEBRECON_RATE_WARN_THRESHOLD = 10

#: Absolute ceiling on bytes read from a single HTTP response (16 MiB).
WEBRECON_RESPONSE_BYTES_HARD_MAX = 16_777_216


class ConfigError(Exception):
    """The configuration is unusable."""


@dataclass
class Limits:
    masscan_rate: int = 1_000
    nuclei_rate: int = 50
    concurrency: int = 8
    nmap_timing: int = 3
    host_timeout_seconds: int = 900
    stage_timeout_seconds: int = 7_200

    def validate(self) -> list[str]:
        warnings: list[str] = []

        if self.masscan_rate < 1:
            raise ConfigError("limits.masscan_rate must be >= 1")
        if self.masscan_rate > MASSCAN_RATE_HARD_MAX:
            warnings.append(
                f"limits.masscan_rate {self.masscan_rate} exceeds the hard maximum "
                f"{MASSCAN_RATE_HARD_MAX} pps and has been clamped"
            )
            self.masscan_rate = MASSCAN_RATE_HARD_MAX
        elif self.masscan_rate > MASSCAN_RATE_WARN_THRESHOLD:
            warnings.append(
                f"limits.masscan_rate {self.masscan_rate} pps is above the safe default "
                f"{MASSCAN_RATE_WARN_THRESHOLD} pps - confirm the client's network can "
                "absorb this before continuing"
            )

        if self.nuclei_rate < 1:
            raise ConfigError("limits.nuclei_rate must be >= 1")
        if self.nuclei_rate > NUCLEI_RATE_HARD_MAX:
            warnings.append(
                f"limits.nuclei_rate {self.nuclei_rate} exceeds the hard maximum "
                f"{NUCLEI_RATE_HARD_MAX} rps and has been clamped"
            )
            self.nuclei_rate = NUCLEI_RATE_HARD_MAX

        if self.concurrency < 1:
            raise ConfigError("limits.concurrency must be >= 1")
        if self.concurrency > CONCURRENCY_HARD_MAX:
            warnings.append(
                f"limits.concurrency {self.concurrency} exceeds the hard maximum "
                f"{CONCURRENCY_HARD_MAX} and has been clamped"
            )
            self.concurrency = CONCURRENCY_HARD_MAX

        if not 0 <= self.nmap_timing <= 5:
            raise ConfigError("limits.nmap_timing must be between 0 and 5")
        if self.nmap_timing >= 5:
            warnings.append(
                "limits.nmap_timing 5 is aggressive and can destabilise fragile hosts"
            )

        if self.host_timeout_seconds < 1:
            raise ConfigError("limits.host_timeout_seconds must be >= 1")
        if self.stage_timeout_seconds < 1:
            raise ConfigError("limits.stage_timeout_seconds must be >= 1")

        return warnings


@dataclass
class Stages:
    discovery: bool = True
    sweep: bool = True
    services: bool = True
    os_detect: bool = False
    scripts: bool = False
    nuclei: bool = False
    webrecon: bool = False

    def enabled_names(self) -> list[str]:
        return [f.name for f in fields(self) if getattr(self, f.name)]


def _normalise_port_spec(value: str, field_name: str) -> str:
    """Strip whitespace and validate a port specification.

    YAML folded scalars introduce spaces, and nmap/masscan both reject a port
    list containing whitespace, so normalise before it reaches an argv.
    """
    cleaned = re.sub(r"\s+", "", str(value))
    if not cleaned:
        raise ConfigError(f"{field_name} must not be empty")
    if not re.fullmatch(r"[0-9,\-]+", cleaned):
        raise ConfigError(
            f"{field_name} must contain only digits, commas and ranges, got {value!r}"
        )
    for part in cleaned.split(","):
        if not part:
            raise ConfigError(f"{field_name} has an empty element: {value!r}")
        bounds = part.split("-")
        if len(bounds) > 2 or any(not b.isdigit() for b in bounds):
            raise ConfigError(f"{field_name} has an invalid element {part!r}")
        numbers = [int(b) for b in bounds]
        if any(not 1 <= n <= 65535 for n in numbers):
            raise ConfigError(f"{field_name} port out of range in {part!r}")
        if len(numbers) == 2 and numbers[0] > numbers[1]:
            raise ConfigError(f"{field_name} has a reversed range {part!r}")
    return cleaned


@dataclass
class Ports:
    #: Ports handed to the fast sweep.
    sweep: str = (
        "21-23,25,53,80,81,88,110,111,135,139,143,161,389,443,445,465,514,515,"
        "587,631,636,873,993,995,1025,1080,1099,1433,1521,1723,1883,2049,2181,"
        "2375,2376,3000,3128,3306,3389,4443,4786,5000,5060,5432,5601,5672,5900,"
        "5985,5986,6000,6379,7001,8000-8010,8080-8090,8443,8888,9000,9042,9090,"
        "9100,9200,9300,10000,11211,15672,27017,27018,50000"
    )
    #: Ports swept when ``--full-ports`` is passed.
    sweep_full: str = "1-65535"
    #: UDP ports for the optional UDP sweep (kept deliberately tiny).
    udp: str = "53,67,123,137,161,500,1900,5353"

    def validate(self) -> list[str]:
        self.sweep = _normalise_port_spec(self.sweep, "ports.sweep")
        self.sweep_full = _normalise_port_spec(self.sweep_full, "ports.sweep_full")
        self.udp = _normalise_port_spec(self.udp, "ports.udp")
        return []


@dataclass
class Discovery:
    method: str = "auto"  # auto | fping | nmap | skip
    fping_retries: int = 2
    fping_timeout_ms: int = 500
    #: Treat every in-scope address as live when discovery finds nothing.
    assume_live_on_empty: bool = False

    def validate(self) -> list[str]:
        if self.method not in {"auto", "fping", "nmap", "skip"}:
            raise ConfigError(
                "discovery.method must be one of: auto, fping, nmap, skip"
            )
        return []


@dataclass
class Sweep:
    backend: str = "auto"  # auto | masscan | naabu | nmap
    udp: bool = False
    retries: int = 1

    def validate(self) -> list[str]:
        if self.backend not in {"auto", "masscan", "naabu", "nmap"}:
            raise ConfigError(
                "sweep.backend must be one of: auto, masscan, naabu, nmap"
            )
        return []


@dataclass
class ServicesCfg:
    version_intensity: int = 5
    banner_grab: bool = False

    def validate(self) -> list[str]:
        if not 0 <= self.version_intensity <= 9:
            raise ConfigError("services.version_intensity must be between 0 and 9")
        return []


@dataclass
class ScriptsCfg:
    #: Only these NSE categories may ever be selected.  See
    #: :mod:`netrecon.stages.scripts` for the expression actually passed to
    #: nmap, which additionally requires ``safe``.
    categories: list[str] = field(default_factory=lambda: ["default", "discovery"])

    def validate(self) -> list[str]:
        from netrecon.stages.scripts import ALLOWED_CATEGORIES, FORBIDDEN_CATEGORIES

        if not self.categories:
            raise ConfigError("scripts.categories must not be empty")
        for category in self.categories:
            lowered = category.strip().lower()
            if lowered in FORBIDDEN_CATEGORIES:
                raise ConfigError(
                    f"NSE category {category!r} is permanently blocked by netrecon"
                )
            if lowered not in ALLOWED_CATEGORIES:
                raise ConfigError(
                    f"NSE category {category!r} is not allowed; permitted categories: "
                    + ", ".join(sorted(ALLOWED_CATEGORIES))
                )
        return []


@dataclass
class NucleiCfg:
    templates: list[str] = field(default_factory=lambda: ["network/"])
    severity: str = "info,low,medium,high,critical"
    concurrency: int = 10
    timeout_seconds: int = 10


@dataclass
class WebReconCfg:
    """Limits for the read-only web recon stage (HTTP GET only)."""

    #: Endpoints probed per run; beyond this the list is truncated and logged.
    max_endpoints: int = 100
    #: Scripts analysed per endpoint (inline scripts count toward this).
    max_scripts_per_endpoint: int = 25
    #: Hard cap on bytes read from any single response.
    max_response_bytes: int = 2_097_152  # 2 MiB
    #: Requests per second across all workers.
    rate_per_second: float = 5.0
    request_timeout_seconds: int = 10
    concurrency: int = 4
    #: Verify TLS certificates. Off by default: in-scope hosts routinely use
    #: self-signed certificates, and failing closed would hide the service.
    verify_tls: bool = False
    #: Mask candidate secrets in the report. The full value stays in the saved
    #: response body under webrecon/ for manual verification.
    redact_secrets: bool = True
    user_agent: str = "netrecon/1.1 (authorised security assessment)"

    def validate(self) -> list[str]:
        warnings: list[str] = []
        if self.max_endpoints < 1:
            raise ConfigError("webrecon.max_endpoints must be >= 1")
        if self.max_scripts_per_endpoint < 1:
            raise ConfigError("webrecon.max_scripts_per_endpoint must be >= 1")
        if self.max_response_bytes < 1024:
            raise ConfigError("webrecon.max_response_bytes must be >= 1024")
        if self.max_response_bytes > WEBRECON_RESPONSE_BYTES_HARD_MAX:
            warnings.append(
                f"webrecon.max_response_bytes {self.max_response_bytes} exceeds the hard "
                f"maximum {WEBRECON_RESPONSE_BYTES_HARD_MAX} and has been clamped"
            )
            self.max_response_bytes = WEBRECON_RESPONSE_BYTES_HARD_MAX
        if self.rate_per_second <= 0:
            raise ConfigError("webrecon.rate_per_second must be > 0")
        if self.rate_per_second > WEBRECON_RATE_HARD_MAX:
            warnings.append(
                f"webrecon.rate_per_second {self.rate_per_second} exceeds the hard maximum "
                f"{WEBRECON_RATE_HARD_MAX} rps and has been clamped"
            )
            self.rate_per_second = float(WEBRECON_RATE_HARD_MAX)
        elif self.rate_per_second > WEBRECON_RATE_WARN_THRESHOLD:
            warnings.append(
                f"webrecon.rate_per_second {self.rate_per_second} is above the safe "
                f"default {WEBRECON_RATE_WARN_THRESHOLD} rps - confirm the target web "
                "services can absorb this"
            )
        if self.request_timeout_seconds < 1:
            raise ConfigError("webrecon.request_timeout_seconds must be >= 1")
        if self.concurrency < 1:
            raise ConfigError("webrecon.concurrency must be >= 1")
        if self.concurrency > CONCURRENCY_HARD_MAX:
            self.concurrency = CONCURRENCY_HARD_MAX
        if not self.redact_secrets:
            warnings.append(
                "webrecon.redact_secrets is off: candidate credentials will be written "
                "to report files in full - handle those files as engagement secrets"
            )
        if not self.user_agent.strip():
            raise ConfigError("webrecon.user_agent must not be empty")
        return warnings


@dataclass
class ScopeCfg:
    max_hosts: int = 65_536
    include_network_broadcast: bool = False

    def validate(self) -> list[str]:
        if self.max_hosts < 1:
            raise ConfigError("scope.max_hosts must be >= 1")
        return []


@dataclass
class Config:
    run_name: str = "default"
    output_dir: str = "results"
    limits: Limits = field(default_factory=Limits)
    stages: Stages = field(default_factory=Stages)
    ports: Ports = field(default_factory=Ports)
    scope: ScopeCfg = field(default_factory=ScopeCfg)
    discovery: Discovery = field(default_factory=Discovery)
    sweep: Sweep = field(default_factory=Sweep)
    services: ServicesCfg = field(default_factory=ServicesCfg)
    scripts: ScriptsCfg = field(default_factory=ScriptsCfg)
    nuclei: NucleiCfg = field(default_factory=NucleiCfg)
    webrecon: WebReconCfg = field(default_factory=WebReconCfg)

    #: Warnings raised while validating, surfaced in the pre-flight summary.
    warnings: list[str] = field(default_factory=list)

    @classmethod
    def load(cls, path: str | Path | None) -> Config:
        data: dict[str, Any] = {}
        if path is not None:
            path = Path(path)
            if not path.is_file():
                raise ConfigError(f"config file not found: {path}")
            try:
                loaded = yaml.safe_load(path.read_text(encoding="utf-8"))
            except yaml.YAMLError as exc:
                raise ConfigError(f"could not parse {path}: {exc}") from exc
            if loaded is None:
                loaded = {}
            if not isinstance(loaded, dict):
                raise ConfigError(f"{path}: top level of the config must be a mapping")
            data = loaded
        return cls.from_dict(data)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Config:
        data = copy.deepcopy(data)
        nested = {
            "limits": Limits,
            "stages": Stages,
            "ports": Ports,
            "scope": ScopeCfg,
            "discovery": Discovery,
            "sweep": Sweep,
            "services": ServicesCfg,
            "scripts": ScriptsCfg,
            "nuclei": NucleiCfg,
            "webrecon": WebReconCfg,
        }
        kwargs: dict[str, Any] = {}
        known_top = {f.name for f in fields(cls)}

        for key, value in data.items():
            if key not in known_top:
                raise ConfigError(f"unknown config key: {key!r}")
            if key in nested:
                if value is None:
                    continue
                if not isinstance(value, dict):
                    raise ConfigError(f"config section {key!r} must be a mapping")
                kwargs[key] = _build_section(nested[key], key, value)
            elif key != "warnings":
                kwargs[key] = value

        config = cls(**kwargs)
        config.validate()
        return config

    def validate(self) -> None:
        warnings: list[str] = []
        for section in (
            self.limits,
            self.ports,
            self.scope,
            self.discovery,
            self.sweep,
            self.services,
            self.scripts,
            self.webrecon,
        ):
            validator = getattr(section, "validate", None)
            if validator is not None:
                warnings.extend(validator())

        if not self.run_name or "/" in self.run_name or self.run_name.startswith("."):
            raise ConfigError(
                "run_name must be a non-empty single path segment (no '/' or leading '.')"
            )

        self.warnings = warnings
        for warning in warnings:
            log.warning("config: %s", warning)

    def to_dict(self) -> dict[str, Any]:
        def unpack(value: Any) -> Any:
            if hasattr(value, "__dataclass_fields__"):
                return {f.name: unpack(getattr(value, f.name)) for f in fields(value)}
            return value

        return {f.name: unpack(getattr(self, f.name)) for f in fields(self)}


def _build_section(section_cls: type, section_name: str, value: dict[str, Any]) -> Any:
    known = {f.name for f in fields(section_cls)}
    unknown = set(value) - known
    if unknown:
        raise ConfigError(
            f"unknown key(s) in config section {section_name!r}: "
            + ", ".join(sorted(unknown))
        )
    return section_cls(**value)
