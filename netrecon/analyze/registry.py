"""Analyzer discovery and selection.

Analyzers are listed explicitly rather than auto-discovered: a recon tool should
not change what it runs because a file appeared on the import path.
"""

from __future__ import annotations

from typing import Any

#: Every analyzer netrecon ships, in report order. Each entry is
#: ``(name, module path, class name)``; modules are imported lazily so a broken
#: analyzer cannot stop the rest of the tool from loading.
ANALYZER_SPECS: tuple[tuple[str, str, str], ...] = (
    ("tls", "netrecon.analyze.tls", "TlsAnalyzer"),
    ("smb", "netrecon.analyze.smb", "SmbAnalyzer"),
    ("database", "netrecon.analyze.database", "DatabaseAnalyzer"),
    ("ssh", "netrecon.analyze.ssh", "SshAnalyzer"),
    ("snmp", "netrecon.analyze.snmp", "SnmpAnalyzer"),
    ("dns", "netrecon.analyze.dns", "DnsAnalyzer"),
    ("mail", "netrecon.analyze.mail", "MailAnalyzer"),
    ("http", "netrecon.analyze.httpsvc", "HttpServiceAnalyzer"),
)

ANALYZER_NAMES: tuple[str, ...] = tuple(name for name, _, _ in ANALYZER_SPECS)


class UnknownAnalyzer(Exception):
    """A configured analyzer name does not exist."""


def build_analyzers(names: list[str] | tuple[str, ...] | None = None) -> list[Any]:
    """Instantiate the named analyzers, or all of them when *names* is None."""
    import importlib

    if names is None:
        selected = ANALYZER_SPECS
    else:
        wanted = [n.strip().lower() for n in names if n and n.strip()]
        unknown = sorted(set(wanted) - set(ANALYZER_NAMES))
        if unknown:
            raise UnknownAnalyzer(
                "unknown analyzer(s): "
                + ", ".join(unknown)
                + "; available: "
                + ", ".join(ANALYZER_NAMES)
            )
        order = {name: index for index, (name, _, _) in enumerate(ANALYZER_SPECS)}
        selected = tuple(
            spec for spec in ANALYZER_SPECS if spec[0] in wanted
        )
        selected = tuple(sorted(selected, key=lambda spec: order[spec[0]]))

    analyzers: list[Any] = []
    for _name, module_path, class_name in selected:
        module = importlib.import_module(module_path)
        analyzers.append(getattr(module, class_name)())
    return analyzers


def validate_names(names: list[str]) -> list[str]:
    """Normalise and check a configured analyzer list."""
    cleaned: list[str] = []
    for name in names:
        lowered = str(name).strip().lower()
        if not lowered:
            continue
        if lowered not in ANALYZER_NAMES:
            raise UnknownAnalyzer(
                f"unknown analyzer {name!r}; available: " + ", ".join(ANALYZER_NAMES)
            )
        if lowered not in cleaned:
            cleaned.append(lowered)
    if not cleaned:
        raise UnknownAnalyzer("no analyzers selected")
    return cleaned
