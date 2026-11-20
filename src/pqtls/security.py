"""Input validation and safe handling helpers."""
from __future__ import annotations

import ipaddress
import re
import stat
from pathlib import Path

_HOST_LABEL = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$")


def normalize_host(value: str) -> str:
    """Validate a DNS name or IP literal; reject URLs, paths and shell metacharacters."""
    candidate = value.strip().rstrip(".")
    if not candidate or len(candidate) > 253 or any(ch in candidate for ch in "/\\@?#"):
        raise ValueError("host must be a DNS name or IP address, not a URL")
    if any(ch.isspace() for ch in candidate):
        raise ValueError("host must not contain whitespace")
    try:
        return str(ipaddress.ip_address(candidate))
    except ValueError:
        pass
    try:
        ascii_name = candidate.encode("idna").decode("ascii").lower()
    except UnicodeError as exc:
        raise ValueError("host is not valid IDNA") from exc
    labels = ascii_name.split(".")
    if not all(_HOST_LABEL.fullmatch(label) for label in labels):
        raise ValueError("host contains an invalid DNS label")
    return ascii_name


def validate_secret_file(path: str) -> None:
    """Require a readable regular file with no group/world permission bits."""
    target = Path(path)
    info = target.stat()
    if not stat.S_ISREG(info.st_mode):
        raise ValueError("secret file must be a regular file")
    if info.st_mode & 0o077:
        raise ValueError("secret file permissions must be 0600 or stricter")
    if not target.is_file():
        raise ValueError("secret file does not exist")
