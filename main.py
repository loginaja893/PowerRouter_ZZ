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
    pass


class Unauthorized(AppError):
    pass


class RateLimited(AppError):
    pass


class Integrity(AppError):
    pass


@dataclasses.dataclass(frozen=True)
class AppConfig:
    app_name: str
    http_host: str
    http_port: int
    db_path: str
    log_level: str
    hmac_secret_b64u: str
    admin_token: str
    allow_private_ips: bool
    max_body_bytes: int
    request_rate_window_s: int
    request_rate_limit: int
    match_batch_limit: int
    match_lookback_s: int

    @staticmethod
    def load(env: t.Mapping[str, str] | None = None) -> "AppConfig":
        if env is None:
            env = os.environ

        def g(key: str, default: str) -> str:
            v = env.get(key, default)
            return v if v is not None else default

        app_name = g("POWERROUTER_APP", "PowerRouter_ZZ")
        http_host = g("POWERROUTER_HOST", "127.0.0.1")
        http_port = int(g("POWERROUTER_PORT", "8787"))
        db_path = g("POWERROUTER_DB", os.path.join(os.getcwd(), "powerrouter_zz.sqlite3"))
        log_level = g("POWERROUTER_LOG", "INFO")
        hmac_secret = g("POWERROUTER_HMAC_SECRET", "")
        admin_token = g("POWERROUTER_ADMIN_TOKEN", "")
        allow_private = g("POWERROUTER_ALLOW_PRIVATE_IPS", "1").strip() not in ("0", "false", "False")
        max_body_bytes = int(g("POWERROUTER_MAX_BODY", "1048576"))
        rate_window = int(g("POWERROUTER_RATE_WINDOW_S", "12"))
        rate_limit = int(g("POWERROUTER_RATE_LIMIT", "220"))
        match_batch_limit = int(g("POWERROUTER_MATCH_BATCH", "256"))
        match_lookback_s = int(g("POWERROUTER_MATCH_LOOKBACK_S", "86400"))

        if not hmac_secret:
            hmac_secret = rand_token(32)
        if not admin_token:
            admin_token = rand_token(24)

        # Normalize secret to urlsafe b64
        try:
            _ = b64u_decode(hmac_secret)
            hmac_secret_b64u = hmac_secret
        except Exception:
            hmac_secret_b64u = b64u(hmac_secret.encode("utf-8"))

        return AppConfig(
            app_name=app_name,
            http_host=http_host,
            http_port=http_port,
            db_path=db_path,
            log_level=log_level.upper(),
            hmac_secret_b64u=hmac_secret_b64u,
            admin_token=admin_token,
            allow_private_ips=allow_private,
            max_body_bytes=max_body_bytes,
            request_rate_window_s=rate_window,
            request_rate_limit=rate_limit,
            match_batch_limit=match_batch_limit,
            match_lookback_s=match_lookback_s,
        )


def configure_logging(level: str) -> None:
    logging.basicConfig(
        level=getattr(logging, level, logging.INFO),
        format="%(asctime)s %(levelname)s %(name)s - %(message)s",
    )


def sqlite_connect(path: str) -> sqlite3.Connection:
    conn = sqlite3.connect(path, isolation_level=None, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    conn.execute("PRAGMA foreign_keys=ON")
    conn.execute("PRAGMA busy_timeout=5000")
    return conn


def _migrations() -> list[tuple[int, str]]:
    return [
        (
            1,
            """
            CREATE TABLE IF NOT EXISTS pr_meta(
              k TEXT PRIMARY KEY,
              v TEXT NOT NULL
            );
            """,
        ),
        (
            2,
            """
            CREATE TABLE IF NOT EXISTS pr_providers(
              provider_id TEXT PRIMARY KEY,
              created_at TEXT NOT NULL,
              updated_at TEXT NOT NULL,
              state TEXT NOT NULL,
              display_name TEXT NOT NULL,
              payout_ref TEXT NOT NULL,
              score REAL NOT NULL,
              stake REAL NOT NULL,
              caps_json TEXT NOT NULL,
              meta_json TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS pr_providers_state ON pr_providers(state);
            """,
        ),
        (
            3,
            """
            CREATE TABLE IF NOT EXISTS pr_offers(
              offer_id TEXT PRIMARY KEY,
              provider_id TEXT NOT NULL,
              created_at TEXT NOT NULL,
              valid_until TEXT NOT NULL,
              token_symbol TEXT NOT NULL,
              unit_price REAL NOT NULL,
              capacity_units INTEGER NOT NULL,
              caps_hash TEXT NOT NULL,
              caps_json TEXT NOT NULL,
              terms_json TEXT NOT NULL,
              status TEXT NOT NULL,
              FOREIGN KEY(provider_id) REFERENCES pr_providers(provider_id) ON DELETE CASCADE
            );
            CREATE INDEX IF NOT EXISTS pr_offers_provider ON pr_offers(provider_id);
            CREATE INDEX IF NOT EXISTS pr_offers_status ON pr_offers(status);
            """,
        ),
        (
            4,
            """
            CREATE TABLE IF NOT EXISTS pr_tickets(
              ticket_id TEXT PRIMARY KEY,
              client_id TEXT NOT NULL,
              created_at TEXT NOT NULL,
              valid_until TEXT NOT NULL,
              deliver_by TEXT NOT NULL,
              token_symbol TEXT NOT NULL,
              max_total REAL NOT NULL,
              units INTEGER NOT NULL,
              req_hash TEXT NOT NULL,
              req_json TEXT NOT NULL,
              meta_json TEXT NOT NULL,
              status TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS pr_tickets_status ON pr_tickets(status);
            CREATE INDEX IF NOT EXISTS pr_tickets_client ON pr_tickets(client_id);
            """,
        ),
        (
            5,
            """
            CREATE TABLE IF NOT EXISTS pr_matches(
              match_id TEXT PRIMARY KEY,
              created_at TEXT NOT NULL,
              ticket_id TEXT NOT NULL,
              offer_id TEXT NOT NULL,
              provider_id TEXT NOT NULL,
              units INTEGER NOT NULL,
              total_price REAL NOT NULL,
              score REAL NOT NULL,
              state TEXT NOT NULL,
              result_hash TEXT,
              meta_json TEXT NOT NULL,
              FOREIGN KEY(ticket_id) REFERENCES pr_tickets(ticket_id) ON DELETE CASCADE,
              FOREIGN KEY(offer_id) REFERENCES pr_offers(offer_id) ON DELETE CASCADE,
              FOREIGN KEY(provider_id) REFERENCES pr_providers(provider_id) ON DELETE CASCADE
            );
            CREATE INDEX IF NOT EXISTS pr_matches_ticket ON pr_matches(ticket_id);
            CREATE INDEX IF NOT EXISTS pr_matches_state ON pr_matches(state);
            """,
        ),
        (
            6,
            """
            CREATE TABLE IF NOT EXISTS pr_audit(
              audit_id TEXT PRIMARY KEY,
              created_at TEXT NOT NULL,
              actor TEXT NOT NULL,
              action TEXT NOT NULL,
              target TEXT NOT NULL,
              payload_json TEXT NOT NULL,
              h TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS pr_audit_actor ON pr_audit(actor);
            CREATE INDEX IF NOT EXISTS pr_audit_action ON pr_audit(action);
            """,
        ),
        (
            7,
            """
            CREATE TABLE IF NOT EXISTS pr_credits(
              owner_id TEXT NOT NULL,
              token_symbol TEXT NOT NULL,
              balance REAL NOT NULL,
              updated_at TEXT NOT NULL,
