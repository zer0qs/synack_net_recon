"""Service categorisation, so reports can be grouped by what a service *is*.

A port alone is weak evidence (anything can listen anywhere), so the service
name reported by ``nmap -sV`` wins when present, and the port number is only a
fallback. Everything unrecognised lands in ``other`` rather than being guessed
at - an unlabelled service in a report is more useful than a wrong label.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

#: Ordered so the most security-relevant categories render first.
CATEGORY_ORDER: tuple[str, ...] = (
    "web",
    "database",
    "remote_access",
    "file_sharing",
    "directory",
    "mail",
    "management",
    "messaging",
    "infrastructure",
    "other",
)

CATEGORY_LABELS: dict[str, str] = {
    "web": "Web services",
    "database": "Databases",
    "remote_access": "Remote access",
    "file_sharing": "File sharing",
    "directory": "Directory services",
    "mail": "Mail services",
    "management": "Management and monitoring",
    "messaging": "Messaging and queues",
    "infrastructure": "Network infrastructure",
    "other": "Other / unclassified",
}

CATEGORY_DESCRIPTIONS: dict[str, str] = {
    "web": "HTTP(S) listeners. Candidates for the web recon stage.",
    "database": "Database engines. Confirm they are not reachable from untrusted networks.",
    "remote_access": "Interactive or administrative access paths.",
    "file_sharing": "File transfer and network file systems.",
    "directory": "Identity and directory protocols.",
    "mail": "Mail transfer and retrieval.",
    "management": "Out-of-band management, monitoring and orchestration APIs.",
    "messaging": "Brokers, queues and caches.",
    "infrastructure": "DNS, DHCP, routing and other network plumbing.",
    "other": "Not matched by name or port; classify manually.",
}

#: nmap service names -> category. Checked before the port table.
SERVICE_NAME_CATEGORIES: dict[str, str] = {
    # web
    "http": "web",
    "https": "web",
    "http-alt": "web",
    "http-proxy": "web",
    "https-alt": "web",
    "ssl/http": "web",
    "ssl/https": "web",
    "http-mgmt": "web",
    "nginx": "web",
    "apache": "web",
    "tomcat": "web",
    "websocket": "web",
    # database
    "mysql": "database",
    "postgresql": "database",
    "ms-sql-s": "database",
    "ms-sql": "database",
    "oracle": "database",
    "oracle-tns": "database",
    "mongodb": "database",
    "mongod": "database",
    "redis": "database",
    "cassandra": "database",
    "couchdb": "database",
    "elasticsearch": "database",
    "memcached": "database",
    "db2": "database",
    "informix": "database",
    "sybase": "database",
    "clickhouse": "database",
    # remote access
    "ssh": "remote_access",
    "telnet": "remote_access",
    "ms-wbt-server": "remote_access",
    "rdp": "remote_access",
    "vnc": "remote_access",
    "vnc-http": "remote_access",
    "x11": "remote_access",
    "rlogin": "remote_access",
    "rsh": "remote_access",
    "rexec": "remote_access",
    "shell": "remote_access",
    "winrm": "remote_access",
    # file sharing
    "ftp": "file_sharing",
    "ftps": "file_sharing",
    "tftp": "file_sharing",
    "nfs": "file_sharing",
    "microsoft-ds": "file_sharing",
    "netbios-ssn": "file_sharing",
    "netbios-ns": "file_sharing",
    "smb": "file_sharing",
    "rsync": "file_sharing",
    "afp": "file_sharing",
    # directory
    "ldap": "directory",
    "ldapssl": "directory",
    "ldaps": "directory",
    "kerberos-sec": "directory",
    "kerberos": "directory",
    "kpasswd": "directory",
    "globalcatldap": "directory",
    # mail
    "smtp": "mail",
    "smtps": "mail",
    "submission": "mail",
    "pop3": "mail",
    "pop3s": "mail",
    "imap": "mail",
    "imaps": "mail",
    # management
    "snmp": "management",
    "ipmi": "management",
    "asf-rmcp": "management",
    "docker": "management",
    "kubernetes": "management",
    "jenkins": "management",
    "zabbix": "management",
    "nagios": "management",
    "prometheus": "management",
    "grafana": "management",
    "jmx": "management",
    "java-rmi": "management",
    "rmiregistry": "management",
    "upnp": "management",
    # messaging
    "amqp": "messaging",
    "mqtt": "messaging",
    "kafka": "messaging",
    "zookeeper": "messaging",
    "stomp": "messaging",
    "nats": "messaging",
    # infrastructure
    "domain": "infrastructure",
    "dns": "infrastructure",
    "dhcps": "infrastructure",
    "dhcpc": "infrastructure",
    "bootps": "infrastructure",
    "ntp": "infrastructure",
    "syslog": "infrastructure",
    "bgp": "infrastructure",
    "isakmp": "infrastructure",
    "sip": "infrastructure",
    "mdns": "infrastructure",
    "rpcbind": "infrastructure",
    "msrpc": "infrastructure",
}

#: Fallback by port, used only when the service name is missing or unknown.
PORT_CATEGORIES: dict[int, str] = {
    21: "file_sharing",
    22: "remote_access",
    23: "remote_access",
    25: "mail",
    53: "infrastructure",
    67: "infrastructure",
    69: "file_sharing",
    80: "web",
    81: "web",
    88: "directory",
    110: "mail",
    111: "infrastructure",
    123: "infrastructure",
    135: "infrastructure",
    137: "file_sharing",
    139: "file_sharing",
    143: "mail",
    161: "management",
    389: "directory",
    443: "web",
    445: "file_sharing",
    465: "mail",
    500: "infrastructure",
    514: "infrastructure",
    515: "other",
    587: "mail",
    623: "management",
    631: "other",
    636: "directory",
    873: "file_sharing",
    993: "mail",
    995: "mail",
    1080: "web",
    1099: "management",
    1433: "database",
    1521: "database",
    1723: "infrastructure",
    1883: "messaging",
    1900: "management",
    2049: "file_sharing",
    2181: "messaging",
    2375: "management",
    2376: "management",
    3000: "web",
    3128: "web",
    3306: "database",
    3389: "remote_access",
    4443: "web",
    4786: "infrastructure",
    5000: "web",
    5060: "infrastructure",
    5353: "infrastructure",
    5432: "database",
    5601: "web",
    5672: "messaging",
    5900: "remote_access",
    5985: "remote_access",
    5986: "remote_access",
    6000: "remote_access",
    6379: "database",
    7001: "web",
    8000: "web",
    8008: "web",
    8080: "web",
    8081: "web",
    8088: "web",
    8443: "web",
    8888: "web",
    9000: "web",
    9042: "database",
    9090: "web",
    9100: "management",
    9200: "database",
    9300: "database",
    10000: "web",
    11211: "database",
    15672: "web",
    27017: "database",
    27018: "database",
    50000: "other",
}

#: Ports conventionally served over TLS, used to pick a scheme for web recon.
TLS_PORTS: frozenset[int] = frozenset(
    {443, 636, 993, 995, 4443, 5986, 8443, 9443, 10443}
)

#: Service names that imply TLS.
TLS_SERVICE_NAMES: frozenset[str] = frozenset(
    {"https", "https-alt", "ssl/http", "ssl/https", "ldapssl", "ldaps", "imaps", "pop3s", "smtps"}
)


def categorise(service_name: str | None, port: int | None) -> str:
    """Return the category for one open port.

    The service name takes precedence; the port table is a fallback only.
    """
    if service_name:
        name = service_name.strip().lower()
        if name in SERVICE_NAME_CATEGORIES:
            return SERVICE_NAME_CATEGORIES[name]
        # nmap prefixes tunnelled services, e.g. "ssl/http".
        if "/" in name:
            tail = name.split("/")[-1]
            if tail in SERVICE_NAME_CATEGORIES:
                return SERVICE_NAME_CATEGORIES[tail]
        if "http" in name:
            return "web"
    if port is not None and port in PORT_CATEGORIES:
        return PORT_CATEGORIES[port]
    return "other"


def is_web_service(service_name: str | None, port: int | None, tunnel: str | None = None) -> bool:
    """True when this port looks like an HTTP(S) listener."""
    if tunnel and tunnel.lower() == "ssl" and categorise(service_name, port) == "web":
        return True
    return categorise(service_name, port) == "web"


def is_tls(service_name: str | None, port: int | None, tunnel: str | None = None) -> bool:
    """Best guess at whether this web port speaks TLS."""
    if tunnel and tunnel.lower() in {"ssl", "tls"}:
        return True
    if service_name and service_name.strip().lower() in TLS_SERVICE_NAMES:
        return True
    return bool(port is not None and port in TLS_PORTS)


@dataclass
class CategoryEntry:
    """One open port, as it appears in a category listing."""

    ip: str
    hostnames: list[str]
    port: int | None
    protocol: str
    service: str | None
    version: str | None
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "ip": self.ip,
            "hostnames": self.hostnames,
            "port": self.port,
            "protocol": self.protocol,
            "service": self.service,
            "version": self.version,
            "notes": self.notes,
        }


@dataclass
class Category:
    key: str
    label: str
    description: str
    entries: list[CategoryEntry] = field(default_factory=list)

    @property
    def host_count(self) -> int:
        return len({entry.ip for entry in self.entries})

    def to_dict(self) -> dict[str, Any]:
        return {
            "key": self.key,
            "label": self.label,
            "description": self.description,
            "port_count": len(self.entries),
            "host_count": self.host_count,
            "entries": [entry.to_dict() for entry in self.entries],
        }


def group_by_category(hosts: list[Any]) -> list[Category]:
    """Build the per-category view from the per-host summaries.

    ``hosts`` are :class:`netrecon.report.build.HostSummary` instances; only the
    attributes used here are required, so this stays easy to test.
    """
    buckets: dict[str, Category] = {
        key: Category(key, CATEGORY_LABELS[key], CATEGORY_DESCRIPTIONS[key])
        for key in CATEGORY_ORDER
    }

    for host in hosts:
        for port in host.open_ports:
            service = port.get("service")
            number = port.get("port")
            key = categorise(service, number)
            buckets[key].entries.append(
                CategoryEntry(
                    ip=host.ip,
                    hostnames=list(host.hostnames),
                    port=number,
                    protocol=port.get("protocol", "tcp"),
                    service=service,
                    version=port.get("version"),
                    notes=[
                        note
                        for note in host.notes
                        if f"`{number}/{port.get('protocol', 'tcp')}`" in note
                    ],
                )
            )

    for category in buckets.values():
        category.entries.sort(key=lambda e: (_ip_key(e.ip), e.protocol, e.port or 0))

    # Drop empty categories so the report only shows what was actually found.
    return [buckets[key] for key in CATEGORY_ORDER if buckets[key].entries]


def web_endpoints(hosts: list[Any]) -> list[dict[str, Any]]:
    """Every in-scope HTTP(S) endpoint found, as web recon input."""
    endpoints: list[dict[str, Any]] = []
    for host in hosts:
        for port in host.open_ports:
            if port.get("protocol", "tcp") != "tcp":
                continue
            service = port.get("service")
            number = port.get("port")
            tunnel = port.get("tunnel")
            if not isinstance(number, int) or not is_web_service(service, number, tunnel):
                continue
            endpoints.append(
                {
                    "ip": host.ip,
                    "port": number,
                    "scheme": "https" if is_tls(service, number, tunnel) else "http",
                    "service": service,
                }
            )
    return endpoints


def _ip_key(ip: str) -> tuple[int, int, str]:
    import ipaddress

    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return (9, 0, ip)
    return (addr.version, int(addr), ip)
