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
              PRIMARY KEY(owner_id, token_symbol)
            );
            """,
        ),
    ]


def db_bootstrap(conn: sqlite3.Connection) -> None:
    conn.execute("BEGIN")
    try:
        for _, sql in _migrations():
            conn.executescript(sql)
        conn.execute("INSERT OR IGNORE INTO pr_meta(k,v) VALUES(?,?)", ("schema_version", "7"))
        conn.execute("COMMIT")
    except Exception:
        conn.execute("ROLLBACK")
        raise


def db_tx(conn: sqlite3.Connection) -> t.Iterator[sqlite3.Connection]:
    conn.execute("BEGIN IMMEDIATE")
    try:
        yield conn
        conn.execute("COMMIT")
    except Exception:
        conn.execute("ROLLBACK")
        raise


def dict_row(row: sqlite3.Row) -> TJSON:
    return {k: row[k] for k in row.keys()}


def _ensure_jsonable(obj: t.Any) -> t.Any:
    if obj is None:
        return None
    if isinstance(obj, (str, int, float, bool)):
        return obj
    if isinstance(obj, (list, tuple)):
        return [_ensure_jsonable(x) for x in obj]
    if isinstance(obj, dict):
        return {str(k): _ensure_jsonable(v) for k, v in obj.items()}
    if dataclasses.is_dataclass(obj):
        return _ensure_jsonable(dataclasses.asdict(obj))
    return str(obj)


def audit_hash(action: str, payload: TJSON) -> str:
    core = {"action": action, "payload": _ensure_jsonable(payload)}
    return stable_hash(core)


@dataclasses.dataclass(frozen=True)
class ProviderCaps:
    gpu: bool
    cpu_arch: str
    ram_gb: int
    vram_gb: int
    regions: list[str]
    labels: list[str]
    isolation: str
    net_mbps: int

    def hash(self) -> str:
        return stable_hash(dataclasses.asdict(self))

    def satisfies(self, req: "TicketReq") -> bool:
        if req.gpu_required and not self.gpu:
            return False
        if req.min_ram_gb and self.ram_gb < req.min_ram_gb:
            return False
        if req.min_vram_gb and self.vram_gb < req.min_vram_gb:
            return False
        if req.min_net_mbps and self.net_mbps < req.min_net_mbps:
            return False
        if req.cpu_arch and req.cpu_arch != self.cpu_arch:
            return False
        if req.isolation and req.isolation != self.isolation:
            return False
        if req.regions_any:
            if not set(req.regions_any).intersection(self.regions):
                return False
        if req.labels_all:
            if not set(req.labels_all).issubset(set(self.labels)):
                return False
        return True


@dataclasses.dataclass(frozen=True)
class TicketReq:
    gpu_required: bool
    cpu_arch: str
    min_ram_gb: int
    min_vram_gb: int
    min_net_mbps: int
    regions_any: list[str]
    labels_all: list[str]
    isolation: str

    def hash(self) -> str:
        return stable_hash(dataclasses.asdict(self))


@dataclasses.dataclass(frozen=True)
class Provider:
    provider_id: str
    created_at: str
    updated_at: str
    state: str
    display_name: str
    payout_ref: str
    score: float
    stake: float
    caps: ProviderCaps
    meta: TJSON


@dataclasses.dataclass(frozen=True)
class Offer:
    offer_id: str
    provider_id: str
    created_at: str
    valid_until: str
    token_symbol: str
    unit_price: float
    capacity_units: int
    caps_hash: str
    caps: ProviderCaps
    terms: TJSON
    status: str


@dataclasses.dataclass(frozen=True)
class Ticket:
    ticket_id: str
    client_id: str
    created_at: str
    valid_until: str
    deliver_by: str
    token_symbol: str
    max_total: float
    units: int
    req_hash: str
    req: TicketReq
    meta: TJSON
    status: str


@dataclasses.dataclass(frozen=True)
class Match:
    match_id: str
    created_at: str
    ticket_id: str
    offer_id: str
    provider_id: str
    units: int
    total_price: float
    score: float
    state: str
    result_hash: str | None
    meta: TJSON


def _random_display_name() -> str:
    words = [
        "saffron",
        "krypton",
        "matrix",
        "lake",
        "ember",
        "vertex",
        "garden",
        "vortex",
        "lime",
        "horizon",
        "riven",
        "delta",
        "ridge",
        "zenith",
        "tundra",
        "cosmic",
        "watt",
        "cipher",
        "spline",
        "pulsar",
        "copper",
        "aurora",
    ]
    a = secrets.choice(words)
    b = secrets.choice(words)
    x = secrets.randbelow(8999) + 101
    return f"{a}-{b}-{x}"


def _safe_float(x: t.Any, *, what: str) -> float:
    try:
        v = float(x)
    except Exception:
        raise BadRequest(f"{what} must be a number")
    if not (v == v) or v in (float("inf"), float("-inf")):
        raise BadRequest(f"{what} must be finite")
    return v


def _safe_int(x: t.Any, *, what: str) -> int:
    try:
        v = int(x)
    except Exception:
        raise BadRequest(f"{what} must be an integer")
    return v


def _must_nonempty_str(x: t.Any, *, what: str, max_len: int = 200) -> str:
    if not isinstance(x, str) or not x.strip():
        raise BadRequest(f"{what} must be a non-empty string")
    s = x.strip()
    if len(s) > max_len:
        raise BadRequest(f"{what} too long")
    return s


def _must_list_str(x: t.Any, *, what: str, max_len: int = 40, max_items: int = 24) -> list[str]:
    if x is None:
        return []
    if not isinstance(x, list):
        raise BadRequest(f"{what} must be a list")
    out: list[str] = []
    for item in x[: max_items + 1]:
        if len(out) >= max_items:
            raise BadRequest(f"{what} too many items")
        out.append(_must_nonempty_str(item, what=what, max_len=max_len))
    return out


def _validate_token_symbol(sym: str) -> str:
    sym = _must_nonempty_str(sym, what="token_symbol", max_len=16).upper()
    if not all(c in (string.ascii_uppercase + string.digits + "_") for c in sym):
        raise BadRequest("token_symbol has invalid characters")
    return sym


def _coerce_caps(d: TJSON) -> ProviderCaps:
    gpu = bool(d.get("gpu", False))
    cpu_arch = _must_nonempty_str(d.get("cpu_arch", "x86_64"), what="caps.cpu_arch", max_len=24)
    ram_gb = max(0, _safe_int(d.get("ram_gb", 0), what="caps.ram_gb"))
    vram_gb = max(0, _safe_int(d.get("vram_gb", 0), what="caps.vram_gb"))
    regions = _must_list_str(d.get("regions", []), what="caps.regions", max_len=32, max_items=16)
    labels = _must_list_str(d.get("labels", []), what="caps.labels", max_len=24, max_items=24)
    isolation = _must_nonempty_str(d.get("isolation", "vm"), what="caps.isolation", max_len=24)
    net_mbps = max(0, _safe_int(d.get("net_mbps", 0), what="caps.net_mbps"))
    return ProviderCaps(
        gpu=gpu,
        cpu_arch=cpu_arch,
        ram_gb=ram_gb,
        vram_gb=vram_gb,
        regions=regions,
        labels=labels,
        isolation=isolation,
        net_mbps=net_mbps,
    )


def _coerce_req(d: TJSON) -> TicketReq:
    gpu_required = bool(d.get("gpu_required", False))
    cpu_arch = _must_nonempty_str(d.get("cpu_arch", ""), what="req.cpu_arch", max_len=24) if d.get("cpu_arch") else ""
    min_ram_gb = max(0, _safe_int(d.get("min_ram_gb", 0), what="req.min_ram_gb"))
    min_vram_gb = max(0, _safe_int(d.get("min_vram_gb", 0), what="req.min_vram_gb"))
    min_net_mbps = max(0, _safe_int(d.get("min_net_mbps", 0), what="req.min_net_mbps"))
    regions_any = _must_list_str(d.get("regions_any", []), what="req.regions_any", max_len=32, max_items=16)
    labels_all = _must_list_str(d.get("labels_all", []), what="req.labels_all", max_len=24, max_items=24)
    isolation = _must_nonempty_str(d.get("isolation", ""), what="req.isolation", max_len=24) if d.get("isolation") else ""
    return TicketReq(
        gpu_required=gpu_required,
        cpu_arch=cpu_arch,
        min_ram_gb=min_ram_gb,
        min_vram_gb=min_vram_gb,
        min_net_mbps=min_net_mbps,
        regions_any=regions_any,
        labels_all=labels_all,
        isolation=isolation,
    )


class HmacTickets:
    def __init__(self, secret_b64u: str):
        self._secret = b64u_decode(secret_b64u)

    def sign(self, purpose: str, claims: TJSON, *, ttl_s: int = 3600) -> str:
        if ttl_s < 1:
            raise BadRequest("ttl too small")
        exp = int(time.time()) + int(ttl_s)
        core = {"p": purpose, "exp": exp, "c": _ensure_jsonable(claims)}
        body = json_dumps(core, pretty=False).encode("utf-8")
        mac = hmac.new(self._secret, body, hashlib.sha256).digest()
        return f"{b64u(body)}.{b64u(mac)}"

    def verify(self, token: str, purpose: str) -> TJSON:
        try:
            a, b = token.split(".", 1)
            body = b64u_decode(a)
            mac = b64u_decode(b)
        except Exception:
            raise Unauthorized("bad token format")
        want = hmac.new(self._secret, body, hashlib.sha256).digest()
        if not hmac.compare_digest(want, mac):
            raise Unauthorized("bad token signature")
        try:
            core = json.loads(body.decode("utf-8"))
        except Exception:
            raise Unauthorized("bad token payload")
        if core.get("p") != purpose:
            raise Unauthorized("bad token purpose")
        exp = int(core.get("exp", 0))
        if int(time.time()) > exp:
            raise Unauthorized("token expired")
        claims = core.get("c", {})
        if not isinstance(claims, dict):
            raise Unauthorized("bad token claims")
        return t.cast(TJSON, claims)


class RateBucket:
    def __init__(self, window_s: int, limit: int):
        self.window_s = int(window_s)
        self.limit = int(limit)
        self._lock = threading.Lock()
        self._buckets: dict[str, list[int]] = {}

    def hit(self, key: str) -> None:
        now = int(time.time())
        with self._lock:
            hist = self._buckets.get(key)
            if hist is None:
                hist = []
                self._buckets[key] = hist
            cutoff = now - self.window_s
            while hist and hist[0] < cutoff:
                hist.pop(0)
            if len(hist) >= self.limit:
                raise RateLimited("rate limit")
            hist.append(now)


class Storage:
    def __init__(self, conn: sqlite3.Connection):
        self.conn = conn

    def _audit(self, actor: str, action: str, target: str, payload: TJSON) -> None:
        aid = "aud_" + uuid.uuid4().hex
        created_at = iso_utc()
        payload_json = json_dumps(payload, pretty=False)
        h = audit_hash(action, payload)
        self.conn.execute(
            "INSERT INTO pr_audit(audit_id,created_at,actor,action,target,payload_json,h) VALUES(?,?,?,?,?,?,?)",
            (aid, created_at, actor, action, target, payload_json, h),
        )

    def list_audit(self, *, limit: int = 200) -> list[TJSON]:
        limit = max(1, min(int(limit), 1000))
        cur = self.conn.execute(
            "SELECT audit_id,created_at,actor,action,target,payload_json,h FROM pr_audit ORDER BY created_at DESC LIMIT ?",
            (limit,),
        )
        rows = []
        for r in cur.fetchall():
            d = dict_row(r)
            d["payload"] = json.loads(d.pop("payload_json"))
            rows.append(d)
        return rows

    # ---- providers ----

    def upsert_provider(
        self,
        *,
        actor: str,
        provider_id: str | None,
        display_name: str | None,
        payout_ref: str,
        stake: float,
        caps: ProviderCaps,
        meta: TJSON,
    ) -> Provider:
        if provider_id is None:
            provider_id = "prov_" + uuid.uuid4().hex
        if display_name is None:
            display_name = _random_display_name()
        now = iso_utc()
        stake = _safe_float(stake, what="stake")
        if stake < 0:
            raise BadRequest("stake must be >= 0")
        payout_ref = _must_nonempty_str(payout_ref, what="payout_ref", max_len=240)
        if len(json_dumps(meta).encode("utf-8")) > 12_000:
            raise BadRequest("meta too large")
        caps_json = json_dumps(dataclasses.asdict(caps), pretty=False)
        meta_json = json_dumps(meta, pretty=False)

        row = self.conn.execute(
            "SELECT provider_id,created_at,updated_at,state,display_name,payout_ref,score,stake,caps_json,meta_json "
            "FROM pr_providers WHERE provider_id=?",
            (provider_id,),
        ).fetchone()
        if row is None:
            created = now
            score = float(0.85 + random.random() * 0.25)
            self.conn.execute(
                "INSERT INTO pr_providers(provider_id,created_at,updated_at,state,display_name,payout_ref,score,stake,caps_json,meta_json) "
                "VALUES(?,?,?,?,?,?,?,?,?,?)",
                (provider_id, created, now, "active", display_name, payout_ref, score, stake, caps_json, meta_json),
            )
            self._audit(actor, "provider.create", provider_id, {"display_name": display_name, "stake": stake, "caps": dataclasses.asdict(caps)})
        else:
            self.conn.execute(
                "UPDATE pr_providers SET updated_at=?, display_name=?, payout_ref=?, stake=?, caps_json=?, meta_json=? WHERE provider_id=?",
                (now, display_name, payout_ref, stake, caps_json, meta_json, provider_id),
            )
            self._audit(actor, "provider.update", provider_id, {"display_name": display_name, "stake": stake, "caps": dataclasses.asdict(caps)})
        return self.get_provider(provider_id)

    def get_provider(self, provider_id: str) -> Provider:
        row = self.conn.execute(
            "SELECT provider_id,created_at,updated_at,state,display_name,payout_ref,score,stake,caps_json,meta_json "
            "FROM pr_providers WHERE provider_id=?",
            (provider_id,),
        ).fetchone()
        if row is None:
            raise NotFound("provider not found")
        caps = _coerce_caps(json.loads(row["caps_json"]))
        meta = json.loads(row["meta_json"])
        return Provider(
            provider_id=row["provider_id"],
            created_at=row["created_at"],
            updated_at=row["updated_at"],
            state=row["state"],
            display_name=row["display_name"],
            payout_ref=row["payout_ref"],
