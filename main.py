"""
PowerRouter_ZZ

A compute matching platform app (single-file) that:
- registers providers/nodes and their capabilities
- accepts client job requests ("tickets") and provider offers
- runs matching and settlement simulations
- persists state in SQLite
- exposes an HTTP+JSON API and a CLI

Design goals: boring-in-production patterns, deterministic persistence, and clear auditability.
"""

from __future__ import annotations

import argparse
import base64
import dataclasses
import datetime as _dt
import hashlib
import hmac
import http.server
import ipaddress
import json
import logging
import os
import random
import secrets
import signal
import sqlite3
import string
import threading
import time
import typing as t
import urllib.parse
import uuid


TJSON = t.Dict[str, t.Any]
LOG = logging.getLogger("PowerRouter_ZZ")


def utc_now() -> _dt.datetime:
    return _dt.datetime.now(tz=_dt.timezone.utc)


def iso_utc(dt: _dt.datetime | None = None) -> str:
    if dt is None:
        dt = utc_now()
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=_dt.timezone.utc)
    return dt.astimezone(_dt.timezone.utc).isoformat().replace("+00:00", "Z")


def parse_iso_utc(s: str) -> _dt.datetime:
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"
    dt = _dt.datetime.fromisoformat(s)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=_dt.timezone.utc)
    return dt.astimezone(_dt.timezone.utc)


def clamp(x: float, lo: float, hi: float) -> float:
    return lo if x < lo else hi if x > hi else x


def b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def b64u_decode(s: str) -> bytes:
    pad = "=" * ((4 - (len(s) % 4)) % 4)
    return base64.urlsafe_b64decode((s + pad).encode("ascii"))


def json_dumps(obj: t.Any, *, pretty: bool = False) -> str:
    if pretty:
        return json.dumps(obj, indent=2, sort_keys=True, ensure_ascii=False)
    return json.dumps(obj, separators=(",", ":"), sort_keys=True, ensure_ascii=False)


def stable_hash(obj: t.Any) -> str:
    raw = json_dumps(obj, pretty=False).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def rand_slug(n: int = 10) -> str:
    alphabet = string.ascii_lowercase + string.digits
    return "".join(secrets.choice(alphabet) for _ in range(n))


def rand_token(nbytes: int = 32) -> str:
    return b64u(secrets.token_bytes(nbytes))


class AppError(RuntimeError):
    pass


class NotFound(AppError):
    pass


class Conflict(AppError):
    pass


class BadRequest(AppError):
