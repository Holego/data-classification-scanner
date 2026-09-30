"""IPv4 / IPv6 address detector backed by the ``ipaddress`` module."""

from __future__ import annotations

import ipaddress
import re
from typing import ClassVar, Iterator

from .base import BaseDetector, Match

_IPV4 = re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w]|\.\d)")
_IPV6 = re.compile(r"(?<![\w:.])(?:[0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f]{0,4}(?![\w:])")


class IPAddressDetector(BaseDetector):
    name: ClassVar[str] = "ip_address"
    description: ClassVar[str] = "IPv4 and IPv6 addresses"
    priority: ClassVar[int] = 80

    def __init__(self, ignore_private: bool = False) -> None:
        self._ignore_private = ignore_private

    def detect(self, text: str) -> Iterator[Match]:
        if "." in text:
            for m in _IPV4.finditer(text):
                addr = self._parse(m.group(0))
                if addr is not None:
                    yield Match(self.name, m.group(0), m.start(), m.end(), "ipv4")
        if ":" in text:
            for m in _IPV6.finditer(text):
                value = m.group(0)
                # "12:30:45" style timestamps never contain "::" or all 8 groups.
                if "::" not in value and value.count(":") != 7:
                    continue
                addr = self._parse(value)
                if addr is not None:
                    yield Match(self.name, value, m.start(), m.end(), "ipv6")

    def _parse(self, value: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
        try:
            addr = ipaddress.ip_address(value)
        except ValueError:
            return None
        if addr.is_unspecified:  # "::" (also "Python :: 3") and 0.0.0.0 carry no information
            return None
        if self._ignore_private and (addr.is_private or addr.is_loopback or addr.is_link_local):
            return None
        return addr

    def mask(self, value: str, subtype: str | None = None) -> str:
        if ":" in value:
            head = [part for part in value.split("::")[0].split(":") if part][:2]
            return (":".join(head) if head else ":") + ":****"
        octets = value.split(".")
        return ".".join(octets[:2] + ["*", "*"])
