"""Validate repository URLs to prevent SSRF."""

from __future__ import annotations

import ipaddress
import socket
from urllib.parse import urlparse

ALLOWED_GIT_HOSTS = frozenset({"github.com", "gitlab.com", "bitbucket.org"})


class InvalidRepoUrlError(ValueError):
    pass


def _is_blocked_ip(addr: str) -> bool:
    try:
        ip = ipaddress.ip_address(addr)
    except ValueError:
        return True
    return (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
    )


def validate_repo_url(url: str) -> str:
    parsed = urlparse(url)
    if parsed.scheme != "https":
        raise InvalidRepoUrlError("Repository URL must use https")
    if not parsed.hostname:
        raise InvalidRepoUrlError("Repository URL must include a host")
    host = parsed.hostname.lower().rstrip(".")
    if host not in ALLOWED_GIT_HOSTS:
        raise InvalidRepoUrlError(
            f"Host {host!r} is not allowed; use github.com, gitlab.com, or bitbucket.org"
        )
    for family, _, _, _, sockaddr in socket.getaddrinfo(host, 443, type=socket.SOCK_STREAM):
        if family in (socket.AF_INET, socket.AF_INET6):
            ip = str(sockaddr[0])
            if _is_blocked_ip(ip):
                raise InvalidRepoUrlError(f"Host {host} resolves to a non-public address")
    path = parsed.path.strip("/")
    if not path:
        raise InvalidRepoUrlError("Repository URL must include owner/repo path")
    return host
