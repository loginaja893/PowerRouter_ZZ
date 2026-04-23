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
            score=float(row["score"]),
            stake=float(row["stake"]),
            caps=caps,
            meta=t.cast(TJSON, meta),
        )

    def list_providers(self, *, state: str | None = None, limit: int = 200) -> list[Provider]:
        limit = max(1, min(int(limit), 2000))
        if state:
            cur = self.conn.execute(
                "SELECT provider_id FROM pr_providers WHERE state=? ORDER BY updated_at DESC LIMIT ?",
                (state, limit),
            )
        else:
            cur = self.conn.execute("SELECT provider_id FROM pr_providers ORDER BY updated_at DESC LIMIT ?", (limit,))
        return [self.get_provider(r["provider_id"]) for r in cur.fetchall()]

    def set_provider_state(self, *, actor: str, provider_id: str, state: str) -> Provider:
        if state not in ("active", "suspended", "retired"):
            raise BadRequest("invalid provider state")
        now = iso_utc()
        row = self.conn.execute(
            "SELECT provider_id,state FROM pr_providers WHERE provider_id=?",
            (provider_id,),
        ).fetchone()
        if row is None:
            raise NotFound("provider not found")
        prior = row["state"]
        self.conn.execute("UPDATE pr_providers SET state=?, updated_at=? WHERE provider_id=?", (state, now, provider_id))
        self._audit(actor, "provider.state", provider_id, {"prior": prior, "next": state})
        return self.get_provider(provider_id)

    # ---- offers ----

    def create_offer(
        self,
        *,
        actor: str,
        provider_id: str,
        valid_until: str,
        token_symbol: str,
        unit_price: float,
        capacity_units: int,
        terms: TJSON,
    ) -> Offer:
        provider = self.get_provider(provider_id)
        if provider.state != "active":
            raise Conflict("provider not active")
        token_symbol = _validate_token_symbol(token_symbol)
        unit_price = _safe_float(unit_price, what="unit_price")
        if unit_price <= 0:
            raise BadRequest("unit_price must be > 0")
        capacity_units = _safe_int(capacity_units, what="capacity_units")
        if capacity_units <= 0:
            raise BadRequest("capacity_units must be > 0")
        vu = parse_iso_utc(valid_until)
        if vu <= utc_now():
            raise BadRequest("valid_until must be in the future")
        if len(json_dumps(terms).encode("utf-8")) > 14_000:
            raise BadRequest("terms too large")
        offer_id = "off_" + uuid.uuid4().hex
        created_at = iso_utc()
        caps_hash = provider.caps.hash()
        caps_json = json_dumps(dataclasses.asdict(provider.caps), pretty=False)
        self.conn.execute(
            "INSERT INTO pr_offers(offer_id,provider_id,created_at,valid_until,token_symbol,unit_price,capacity_units,caps_hash,caps_json,terms_json,status) "
            "VALUES(?,?,?,?,?,?,?,?,?,?,?)",
            (
                offer_id,
                provider_id,
                created_at,
                iso_utc(vu),
                token_symbol,
                unit_price,
                capacity_units,
                caps_hash,
                caps_json,
                json_dumps(terms, pretty=False),
                "open",
            ),
        )
        self._audit(actor, "offer.create", offer_id, {"provider_id": provider_id, "token_symbol": token_symbol, "unit_price": unit_price, "capacity_units": capacity_units})
        return self.get_offer(offer_id)

    def get_offer(self, offer_id: str) -> Offer:
        row = self.conn.execute(
            "SELECT offer_id,provider_id,created_at,valid_until,token_symbol,unit_price,capacity_units,caps_hash,caps_json,terms_json,status "
            "FROM pr_offers WHERE offer_id=?",
            (offer_id,),
        ).fetchone()
        if row is None:
            raise NotFound("offer not found")
        caps = _coerce_caps(json.loads(row["caps_json"]))
        terms = json.loads(row["terms_json"])
        return Offer(
            offer_id=row["offer_id"],
            provider_id=row["provider_id"],
            created_at=row["created_at"],
            valid_until=row["valid_until"],
            token_symbol=row["token_symbol"],
            unit_price=float(row["unit_price"]),
            capacity_units=int(row["capacity_units"]),
            caps_hash=row["caps_hash"],
            caps=caps,
            terms=t.cast(TJSON, terms),
            status=row["status"],
        )

    def list_offers(self, *, status: str = "open", limit: int = 200) -> list[Offer]:
        limit = max(1, min(int(limit), 2000))
        cur = self.conn.execute(
            "SELECT offer_id FROM pr_offers WHERE status=? ORDER BY created_at DESC LIMIT ?",
            (status, limit),
        )
        return [self.get_offer(r["offer_id"]) for r in cur.fetchall()]

    def close_offer(self, *, actor: str, offer_id: str, reason: str) -> Offer:
        reason = _must_nonempty_str(reason, what="reason", max_len=140)
        row = self.conn.execute("SELECT status FROM pr_offers WHERE offer_id=?", (offer_id,)).fetchone()
        if row is None:
            raise NotFound("offer not found")
        if row["status"] != "open":
            raise Conflict("offer not open")
        self.conn.execute("UPDATE pr_offers SET status=? WHERE offer_id=?", ("closed", offer_id))
        self._audit(actor, "offer.close", offer_id, {"reason": reason})
        return self.get_offer(offer_id)

    # ---- tickets ----

    def create_ticket(
        self,
        *,
        actor: str,
        client_id: str,
        valid_until: str,
        deliver_by: str,
        token_symbol: str,
        max_total: float,
        units: int,
        req: TicketReq,
        meta: TJSON,
    ) -> Ticket:
        client_id = _must_nonempty_str(client_id, what="client_id", max_len=120)
        token_symbol = _validate_token_symbol(token_symbol)
        max_total = _safe_float(max_total, what="max_total")
        if max_total <= 0:
            raise BadRequest("max_total must be > 0")
        units = _safe_int(units, what="units")
        if units <= 0:
            raise BadRequest("units must be > 0")

        vu = parse_iso_utc(valid_until)
        db = parse_iso_utc(deliver_by)
        now = utc_now()
        if vu <= now:
            raise BadRequest("valid_until must be in the future")
        if db <= now:
            raise BadRequest("deliver_by must be in the future")
        if db <= vu:
            raise BadRequest("deliver_by must be after valid_until")
        if (db - now).total_seconds() < 600:
            raise BadRequest("deliver_by too soon")
        if (db - now).total_seconds() > 60 * 60 * 24 * 19:
            raise BadRequest("deliver_by too far")

        if len(json_dumps(meta).encode("utf-8")) > 14_000:
            raise BadRequest("meta too large")

        ticket_id = "tix_" + uuid.uuid4().hex
        created_at = iso_utc()
        req_hash = req.hash()
        self.conn.execute(
            "INSERT INTO pr_tickets(ticket_id,client_id,created_at,valid_until,deliver_by,token_symbol,max_total,units,req_hash,req_json,meta_json,status) "
            "VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                ticket_id,
                client_id,
                created_at,
                iso_utc(vu),
                iso_utc(db),
                token_symbol,
                max_total,
                units,
                req_hash,
                json_dumps(dataclasses.asdict(req), pretty=False),
                json_dumps(meta, pretty=False),
                "open",
            ),
        )
        self._audit(actor, "ticket.create", ticket_id, {"client_id": client_id, "token_symbol": token_symbol, "max_total": max_total, "units": units, "req": dataclasses.asdict(req)})
        return self.get_ticket(ticket_id)

    def get_ticket(self, ticket_id: str) -> Ticket:
        row = self.conn.execute(
            "SELECT ticket_id,client_id,created_at,valid_until,deliver_by,token_symbol,max_total,units,req_hash,req_json,meta_json,status "
            "FROM pr_tickets WHERE ticket_id=?",
            (ticket_id,),
        ).fetchone()
        if row is None:
            raise NotFound("ticket not found")
        req = _coerce_req(json.loads(row["req_json"]))
        meta = json.loads(row["meta_json"])
        return Ticket(
            ticket_id=row["ticket_id"],
            client_id=row["client_id"],
            created_at=row["created_at"],
            valid_until=row["valid_until"],
            deliver_by=row["deliver_by"],
            token_symbol=row["token_symbol"],
            max_total=float(row["max_total"]),
            units=int(row["units"]),
            req_hash=row["req_hash"],
            req=req,
            meta=t.cast(TJSON, meta),
            status=row["status"],
        )

    def list_tickets(self, *, status: str = "open", limit: int = 200) -> list[Ticket]:
        limit = max(1, min(int(limit), 2000))
        cur = self.conn.execute(
            "SELECT ticket_id FROM pr_tickets WHERE status=? ORDER BY created_at DESC LIMIT ?",
            (status, limit),
        )
        return [self.get_ticket(r["ticket_id"]) for r in cur.fetchall()]

    def close_ticket(self, *, actor: str, ticket_id: str, reason: str) -> Ticket:
        reason = _must_nonempty_str(reason, what="reason", max_len=140)
        row = self.conn.execute("SELECT status FROM pr_tickets WHERE ticket_id=?", (ticket_id,)).fetchone()
        if row is None:
            raise NotFound("ticket not found")
        if row["status"] != "open":
            raise Conflict("ticket not open")
        self.conn.execute("UPDATE pr_tickets SET status=? WHERE ticket_id=?", ("closed", ticket_id))
        self._audit(actor, "ticket.close", ticket_id, {"reason": reason})
        return self.get_ticket(ticket_id)

    # ---- credits ----

    def _get_credit(self, owner_id: str, token_symbol: str) -> float:
        row = self.conn.execute(
            "SELECT balance FROM pr_credits WHERE owner_id=? AND token_symbol=?",
            (owner_id, token_symbol),
        ).fetchone()
        return float(row["balance"]) if row is not None else 0.0

    def credit(self, *, actor: str, owner_id: str, token_symbol: str, delta: float, reason: str) -> float:
        token_symbol = _validate_token_symbol(token_symbol)
        delta = _safe_float(delta, what="delta")
        if delta == 0:
            return self._get_credit(owner_id, token_symbol)
        reason = _must_nonempty_str(reason, what="reason", max_len=140)
        cur = self._get_credit(owner_id, token_symbol)
        nxt = cur + delta
        if nxt < -1e-9:
            raise Integrity("insufficient balance")
        now = iso_utc()
        self.conn.execute(
            "INSERT INTO pr_credits(owner_id,token_symbol,balance,updated_at) VALUES(?,?,?,?) "
            "ON CONFLICT(owner_id,token_symbol) DO UPDATE SET balance=excluded.balance, updated_at=excluded.updated_at",
            (owner_id, token_symbol, nxt, now),
        )
        self._audit(actor, "credit.delta", f"{owner_id}:{token_symbol}", {"delta": delta, "reason": reason, "prior": cur, "next": nxt})
        return nxt

    def credits_of(self, owner_id: str) -> dict[str, float]:
        cur = self.conn.execute("SELECT token_symbol,balance FROM pr_credits WHERE owner_id=? ORDER BY token_symbol", (owner_id,))
        out: dict[str, float] = {}
        for r in cur.fetchall():
            out[r["token_symbol"]] = float(r["balance"])
        return out

    # ---- matches ----

    def create_match(
        self,
        *,
        actor: str,
        ticket_id: str,
        offer_id: str,
        units: int,
        total_price: float,
        score: float,
        meta: TJSON,
    ) -> Match:
        ticket = self.get_ticket(ticket_id)
        offer = self.get_offer(offer_id)
        if ticket.status != "open":
            raise Conflict("ticket not open")
        if offer.status != "open":
            raise Conflict("offer not open")

        now = utc_now()
        if parse_iso_utc(ticket.valid_until) <= now:
            raise Conflict("ticket expired")
        if parse_iso_utc(offer.valid_until) <= now:
            raise Conflict("offer expired")

        if ticket.token_symbol != offer.token_symbol:
            raise BadRequest("token mismatch")
        if units <= 0:
            raise BadRequest("units must be > 0")
        if units > ticket.units:
            raise BadRequest("units exceed ticket")
        if units > offer.capacity_units:
            raise BadRequest("units exceed offer capacity")
        total_price = _safe_float(total_price, what="total_price")
        if total_price <= 0:
            raise BadRequest("total_price must be > 0")
        if total_price > ticket.max_total + 1e-9:
            raise BadRequest("total_price exceeds ticket max_total")
        score = _safe_float(score, what="score")
        if len(json_dumps(meta).encode("utf-8")) > 12_000:
            raise BadRequest("meta too large")

        match_id = "mat_" + uuid.uuid4().hex
        created_at = iso_utc()
        self.conn.execute(
            "INSERT INTO pr_matches(match_id,created_at,ticket_id,offer_id,provider_id,units,total_price,score,state,result_hash,meta_json) "
            "VALUES(?,?,?,?,?,?,?,?,?,?,?)",
            (
                match_id,
                created_at,
                ticket_id,
                offer_id,
                offer.provider_id,
                units,
                total_price,
                score,
                "matched",
                None,
                json_dumps(meta, pretty=False),
            ),
        )

        # Reserve capacity immediately and close ticket + offer (simple, safe default).
        self.conn.execute("UPDATE pr_tickets SET status=? WHERE ticket_id=?", ("matched", ticket_id))
        self.conn.execute("UPDATE pr_offers SET status=? WHERE offer_id=?", ("matched", offer_id))

        # Credit escrow to "router" then pay provider later (sim).
        self.credit(actor=actor, owner_id="router", token_symbol=ticket.token_symbol, delta=total_price, reason="escrow.lock")

        self._audit(actor, "match.create", match_id, {"ticket_id": ticket_id, "offer_id": offer_id, "units": units, "total_price": total_price, "score": score})
        return self.get_match(match_id)

    def get_match(self, match_id: str) -> Match:
        row = self.conn.execute(
            "SELECT match_id,created_at,ticket_id,offer_id,provider_id,units,total_price,score,state,result_hash,meta_json "
            "FROM pr_matches WHERE match_id=?",
            (match_id,),
        ).fetchone()
        if row is None:
            raise NotFound("match not found")
        meta = json.loads(row["meta_json"])
        return Match(
            match_id=row["match_id"],
            created_at=row["created_at"],
            ticket_id=row["ticket_id"],
            offer_id=row["offer_id"],
            provider_id=row["provider_id"],
            units=int(row["units"]),
            total_price=float(row["total_price"]),
            score=float(row["score"]),
            state=row["state"],
            result_hash=row["result_hash"],
            meta=t.cast(TJSON, meta),
        )

    def list_matches(self, *, state: str | None = None, limit: int = 200) -> list[Match]:
        limit = max(1, min(int(limit), 3000))
        if state:
            cur = self.conn.execute(
                "SELECT match_id FROM pr_matches WHERE state=? ORDER BY created_at DESC LIMIT ?",
                (state, limit),
            )
        else:
            cur = self.conn.execute("SELECT match_id FROM pr_matches ORDER BY created_at DESC LIMIT ?", (limit,))
        return [self.get_match(r["match_id"]) for r in cur.fetchall()]

    def deliver_result(self, *, actor: str, match_id: str, result_blob: bytes, meta: TJSON) -> Match:
        m = self.get_match(match_id)
        if m.state != "matched":
            raise Conflict("match not deliverable")
        if len(result_blob) > 2_500_000:
            raise BadRequest("result too large")
        h = hashlib.sha256(result_blob).hexdigest()
        now = iso_utc()
        self.conn.execute(
            "UPDATE pr_matches SET state=?, result_hash=?, meta_json=? WHERE match_id=?",
            ("delivered", h, json_dumps(meta, pretty=False), match_id),
        )
        self._audit(actor, "match.deliver", match_id, {"result_hash": h, "bytes": len(result_blob), "at": now})
        return self.get_match(match_id)

    def finalize_match(self, *, actor: str, match_id: str, fee_bps: int = 247, treasury_owner: str = "treasury") -> Match:
        m = self.get_match(match_id)
        if m.state != "delivered":
            raise Conflict("match not finalizable")
        fee_bps = max(0, min(int(fee_bps), 900))
        fee = m.total_price * (fee_bps / 10_000.0)
        pay = m.total_price - fee
        ticket = self.get_ticket(m.ticket_id)
        self.credit(actor=actor, owner_id="router", token_symbol=ticket.token_symbol, delta=-m.total_price, reason="escrow.release")
        self.credit(actor=actor, owner_id=m.provider_id, token_symbol=ticket.token_symbol, delta=pay, reason="provider.payout")
        self.credit(actor=actor, owner_id=treasury_owner, token_symbol=ticket.token_symbol, delta=fee, reason="router.fee")
        self.conn.execute("UPDATE pr_matches SET state=? WHERE match_id=?", ("finalized", match_id))
        self._audit(actor, "match.finalize", match_id, {"fee_bps": fee_bps, "fee": fee, "pay": pay})
        # Also open new capacity by setting offer/ticket to closed rather than matched.
        self.conn.execute("UPDATE pr_tickets SET status=? WHERE ticket_id=?", ("closed", m.ticket_id))
        self.conn.execute("UPDATE pr_offers SET status=? WHERE offer_id=?", ("closed", m.offer_id))
        return self.get_match(match_id)


class Matcher:
    def __init__(self, st: Storage):
        self.st = st

    def _offer_score(self, provider: Provider, offer: Offer, ticket: Ticket) -> float:
        # Lower price wins, higher provider score wins, earlier expiry penalized.
        price_component = (ticket.max_total / max(offer.unit_price * ticket.units, 1e-9))
        score_component = provider.score
        caps_bonus = 0.0
        if provider.caps.gpu and ticket.req.gpu_required:
            caps_bonus += 0.55
        if provider.caps.isolation == "tee":
            caps_bonus += 0.22
        if "green" in (label.lower() for label in provider.caps.labels):
            caps_bonus += 0.14
        # Expiry distance
        now = utc_now()
        exp_offer = parse_iso_utc(offer.valid_until)
        exp_ticket = parse_iso_utc(ticket.valid_until)
        exp_s = min((exp_offer - now).total_seconds(), (exp_ticket - now).total_seconds())
        expiry_component = clamp(exp_s / 3600.0, 0.1, 48.0) / 8.0
        raw = 0.80 * price_component + 0.75 * score_component + 0.30 * expiry_component + caps_bonus
        return clamp(raw, 0.01, 999.0)

    def suggest_matches(self, *, limit: int = 50) -> list[TJSON]:
        offers = self.st.list_offers(status="open", limit=5000)
        tickets = self.st.list_tickets(status="open", limit=2500)
        if not offers or not tickets:
            return []

        providers_cache: dict[str, Provider] = {}
        out: list[TJSON] = []
        for tix in tickets:
            if parse_iso_utc(tix.valid_until) <= utc_now():
                continue
            best: tuple[float, Offer] | None = None
            for off in offers:
                if off.token_symbol != tix.token_symbol:
                    continue
                if parse_iso_utc(off.valid_until) <= utc_now():
                    continue
                if off.capacity_units < tix.units:
                    continue
                prov = providers_cache.get(off.provider_id)
                if prov is None:
                    prov = self.st.get_provider(off.provider_id)
                    providers_cache[off.provider_id] = prov
                if prov.state != "active":
                    continue
                if not prov.caps.satisfies(tix.req):
                    continue
                total_price = off.unit_price * tix.units
                if total_price > tix.max_total + 1e-9:
                    continue
                s = self._offer_score(prov, off, tix)
                if best is None or s > best[0]:
                    best = (s, off)
            if best is None:
                continue
            score, off = best
            out.append(
                {
                    "ticket_id": tix.ticket_id,
                    "offer_id": off.offer_id,
                    "provider_id": off.provider_id,
                    "units": tix.units,
                    "total_price": round(off.unit_price * tix.units, 10),
                    "score": round(score, 10),
                }
            )
        out.sort(key=lambda x: float(x["score"]), reverse=True)
        return out[: max(0, int(limit))]

    def execute_best(self, *, actor: str, limit: int = 1) -> list[Match]:
        picks = self.suggest_matches(limit=max(1, int(limit)))
        out: list[Match] = []
        for pick in picks:
            m = self.st.create_match(
                actor=actor,
                ticket_id=pick["ticket_id"],
                offer_id=pick["offer_id"],
                units=int(pick["units"]),
                total_price=float(pick["total_price"]),
                score=float(pick["score"]),
                meta={"engine": "PowerRouter_ZZ", "picked_at": iso_utc()},
            )
            out.append(m)
        return out


def safe_client_ip(handler: http.server.BaseHTTPRequestHandler, *, allow_private: bool) -> str:
    addr = handler.client_address[0]
    try:
        ip = ipaddress.ip_address(addr)
    except Exception:
        return "unknown"
    if not allow_private and (ip.is_private or ip.is_loopback or ip.is_link_local):
        raise Unauthorized("private ip not allowed")
    return str(ip)


def read_body(handler: http.server.BaseHTTPRequestHandler, max_bytes: int) -> bytes:
    ln = handler.headers.get("Content-Length")
    if ln is None:
        return b""
    try:
        n = int(ln)
    except Exception:
        raise BadRequest("invalid Content-Length")
    if n < 0 or n > max_bytes:
        raise BadRequest("body too large")
    data = handler.rfile.read(n)
    if len(data) != n:
        raise BadRequest("short read")
    return data


def parse_json_body(handler: http.server.BaseHTTPRequestHandler, max_bytes: int) -> TJSON:
    data = read_body(handler, max_bytes)
    if not data:
        return {}
    ctype = handler.headers.get("Content-Type", "")
    if "application/json" not in ctype:
        raise BadRequest("Content-Type must be application/json")
    try:
        obj = json.loads(data.decode("utf-8"))
    except Exception:
        raise BadRequest("invalid json")
    if not isinstance(obj, dict):
        raise BadRequest("json body must be an object")
    return t.cast(TJSON, obj)


def path_parts(path: str) -> list[str]:
    p = urllib.parse.urlparse(path).path
    parts = [x for x in p.split("/") if x]
    return parts


def qparams(path: str) -> dict[str, str]:
    q = urllib.parse.urlparse(path).query
    parsed = urllib.parse.parse_qs(q, keep_blank_values=True)
    out: dict[str, str] = {}
    for k, vs in parsed.items():
        if not vs:
            continue
        out[k] = vs[-1]
    return out


def json_response(handler: http.server.BaseHTTPRequestHandler, code: int, obj: t.Any, headers: dict[str, str] | None = None) -> None:
    raw = json_dumps(obj, pretty=False).encode("utf-8")
    handler.send_response(code)
    handler.send_header("Content-Type", "application/json; charset=utf-8")
    handler.send_header("Content-Length", str(len(raw)))
    handler.send_header("Cache-Control", "no-store")
    if headers:
        for k, v in headers.items():
            handler.send_header(k, v)
    handler.end_headers()
    handler.wfile.write(raw)


def problem(code: int, msg: str, *, detail: t.Any = None) -> TJSON:
    d: TJSON = {"error": msg}
    if detail is not None:
        d["detail"] = detail
    d["ts"] = iso_utc()
    return d


class App:
    def __init__(self, cfg: AppConfig):
        self.cfg = cfg
        self.conn = sqlite_connect(cfg.db_path)
        db_bootstrap(self.conn)
        self.st = Storage(self.conn)
        self.matcher = Matcher(self.st)
        self.tokens = HmacTickets(cfg.hmac_secret_b64u)
        self.rate = RateBucket(cfg.request_rate_window_s, cfg.request_rate_limit)

    def close(self) -> None:
        try:
            self.conn.close()
        except Exception:
            pass

    # ---- auth ----

    def require_admin(self, handler: http.server.BaseHTTPRequestHandler) -> None:
        token = handler.headers.get("Authorization", "").strip()
        if not token.startswith("Bearer "):
            raise Unauthorized("missing bearer")
        if token[len("Bearer ") :] != self.cfg.admin_token:
            raise Unauthorized("bad admin token")

    def issue_actor_token(self, actor_id: str, *, ttl_s: int = 6 * 3600) -> str:
        actor_id = _must_nonempty_str(actor_id, what="actor_id", max_len=120)
        return self.tokens.sign("actor", {"actor_id": actor_id}, ttl_s=ttl_s)

    def actor_from_request(self, handler: http.server.BaseHTTPRequestHandler) -> str:
        auth = handler.headers.get("Authorization", "").strip()
        if auth.startswith("Bearer "):
            tok = auth[len("Bearer ") :]
            claims = self.tokens.verify(tok, "actor")
            actor = _must_nonempty_str(claims.get("actor_id", ""), what="actor_id", max_len=120)
            return actor
        return "anonymous"

class Handler(http.server.BaseHTTPRequestHandler):
    server_version = "PowerRouter_ZZ/1.0"
    app: App

    def log_message(self, fmt: str, *args: t.Any) -> None:
        LOG.info("%s - %s", self.address_string(), fmt % args)

    def _dispatch(self) -> None:
        cfg = self.app.cfg
        ip = safe_client_ip(self, allow_private=cfg.allow_private_ips)
        self.app.rate.hit(ip)

        parts = path_parts(self.path)
        method = self.command.upper()

        if method == "GET" and not parts:
            return json_response(self, 200, {"app": cfg.app_name, "ts": iso_utc(), "db": os.path.basename(cfg.db_path)})

        # health + meta
        if method == "GET" and parts == ["health"]:
            return json_response(self, 200, {"ok": True, "ts": iso_utc()})
        if method == "GET" and parts == ["meta"]:
            return json_response(
                self,
                200,
                {
                    "app": cfg.app_name,
                    "ts": iso_utc(),
                    "max_body": cfg.max_body_bytes,
                    "rate_window_s": cfg.request_rate_window_s,
                    "rate_limit": cfg.request_rate_limit,
                    "match_batch": cfg.match_batch_limit,
                    "match_lookback_s": cfg.match_lookback_s,
                },
            )

        # admin: token mint
        if method == "POST" and parts == ["admin", "actor-token"]:
            self.app.require_admin(self)
            body = parse_json_body(self, cfg.max_body_bytes)
            actor_id = _must_nonempty_str(body.get("actor_id", ""), what="actor_id", max_len=120)
            ttl_s = _safe_int(body.get("ttl_s", 6 * 3600), what="ttl_s")
            tok = self.app.issue_actor_token(actor_id, ttl_s=ttl_s)
            return json_response(self, 200, {"token": tok, "actor_id": actor_id, "ttl_s": ttl_s})

        actor = self.app.actor_from_request(self)

        # providers
        if method == "GET" and parts == ["providers"]:
            qp = qparams(self.path)
            state = qp.get("state")
            limit = int(qp.get("limit", "200"))
            providers = self.app.st.list_providers(state=state, limit=limit)
            return json_response(self, 200, {"items": [dataclasses.asdict(p) | {"caps": dataclasses.asdict(p.caps)} for p in providers]})
        if method == "GET" and len(parts) == 2 and parts[0] == "providers":
            p = self.app.st.get_provider(parts[1])
            return json_response(self, 200, {"provider": dataclasses.asdict(p) | {"caps": dataclasses.asdict(p.caps)}})
        if method == "POST" and parts == ["providers"]:
            body = parse_json_body(self, cfg.max_body_bytes)
            caps = _coerce_caps(t.cast(TJSON, body.get("caps", {})))
            meta = t.cast(TJSON, body.get("meta", {})) if isinstance(body.get("meta", {}), dict) else {}
            stake = _safe_float(body.get("stake", 0.0), what="stake")
            payout_ref = _must_nonempty_str(body.get("payout_ref", "pay:" + rand_slug(18)), what="payout_ref", max_len=240)
            display_name = body.get("display_name")
            if display_name is not None:
                display_name = _must_nonempty_str(display_name, what="display_name", max_len=120)
            prov = self.app.st.upsert_provider(
                actor=actor,
                provider_id=None,
                display_name=t.cast(str | None, display_name),
                payout_ref=payout_ref,
                stake=stake,
                caps=caps,
                meta=meta,
            )
            return json_response(self, 201, {"provider": dataclasses.asdict(prov) | {"caps": dataclasses.asdict(prov.caps)}})
        if method == "POST" and len(parts) == 3 and parts[0] == "providers" and parts[2] == "state":
            body = parse_json_body(self, cfg.max_body_bytes)
            state = _must_nonempty_str(body.get("state", ""), what="state", max_len=24)
            prov = self.app.st.set_provider_state(actor=actor, provider_id=parts[1], state=state)
            return json_response(self, 200, {"provider": dataclasses.asdict(prov) | {"caps": dataclasses.asdict(prov.caps)}})

        # offers
        if method == "GET" and parts == ["offers"]:
            qp = qparams(self.path)
            status = qp.get("status", "open")
            limit = int(qp.get("limit", "200"))
            offers = self.app.st.list_offers(status=status, limit=limit)
            items = []
            for o in offers:
                items.append(dataclasses.asdict(o) | {"caps": dataclasses.asdict(o.caps)})
            return json_response(self, 200, {"items": items})
        if method == "GET" and len(parts) == 2 and parts[0] == "offers":
            o = self.app.st.get_offer(parts[1])
            return json_response(self, 200, {"offer": dataclasses.asdict(o) | {"caps": dataclasses.asdict(o.caps)}})
        if method == "POST" and parts == ["offers"]:
            body = parse_json_body(self, cfg.max_body_bytes)
            provider_id = _must_nonempty_str(body.get("provider_id", ""), what="provider_id", max_len=100)
            token_symbol = _validate_token_symbol(str(body.get("token_symbol", "ETH")))
            unit_price = _safe_float(body.get("unit_price", 1.0), what="unit_price")
            capacity_units = _safe_int(body.get("capacity_units", 1), what="capacity_units")
            mins = _safe_int(body.get("valid_mins", 90), what="valid_mins")
            if mins < 5 or mins > 24 * 60:
                raise BadRequest("valid_mins out of range")
            valid_until = iso_utc(utc_now() + _dt.timedelta(minutes=mins))
            terms = t.cast(TJSON, body.get("terms", {})) if isinstance(body.get("terms", {}), dict) else {}
            offer = self.app.st.create_offer(
                actor=actor,
                provider_id=provider_id,
                valid_until=valid_until,
                token_symbol=token_symbol,
                unit_price=unit_price,
                capacity_units=capacity_units,
                terms=terms,
            )
            return json_response(self, 201, {"offer": dataclasses.asdict(offer) | {"caps": dataclasses.asdict(offer.caps)}})
        if method == "POST" and len(parts) == 3 and parts[0] == "offers" and parts[2] == "close":
            body = parse_json_body(self, cfg.max_body_bytes)
            reason = _must_nonempty_str(body.get("reason", "manual"), what="reason", max_len=140)
            offer = self.app.st.close_offer(actor=actor, offer_id=parts[1], reason=reason)
            return json_response(self, 200, {"offer": dataclasses.asdict(offer) | {"caps": dataclasses.asdict(offer.caps)}})

        # tickets
        if method == "GET" and parts == ["tickets"]:
            qp = qparams(self.path)
            status = qp.get("status", "open")
            limit = int(qp.get("limit", "200"))
            tickets = self.app.st.list_tickets(status=status, limit=limit)
            items = []
            for k in tickets:
                items.append(dataclasses.asdict(k) | {"req": dataclasses.asdict(k.req)})
            return json_response(self, 200, {"items": items})
        if method == "GET" and len(parts) == 2 and parts[0] == "tickets":
            k = self.app.st.get_ticket(parts[1])
            return json_response(self, 200, {"ticket": dataclasses.asdict(k) | {"req": dataclasses.asdict(k.req)}})
        if method == "POST" and parts == ["tickets"]:
            body = parse_json_body(self, cfg.max_body_bytes)
            client_id = _must_nonempty_str(body.get("client_id", "cli_" + rand_slug(10)), what="client_id", max_len=120)
            token_symbol = _validate_token_symbol(str(body.get("token_symbol", "ETH")))
            max_total = _safe_float(body.get("max_total", 10.0), what="max_total")
            units = _safe_int(body.get("units", 1), what="units")
            valid_mins = _safe_int(body.get("valid_mins", 30), what="valid_mins")
            deliver_mins = _safe_int(body.get("deliver_mins", 180), what="deliver_mins")
            if valid_mins < 5 or valid_mins > 12 * 60:
                raise BadRequest("valid_mins out of range")
            if deliver_mins < valid_mins + 10 or deliver_mins > 19 * 24 * 60:
                raise BadRequest("deliver_mins out of range")
            valid_until = iso_utc(utc_now() + _dt.timedelta(minutes=valid_mins))
            deliver_by = iso_utc(utc_now() + _dt.timedelta(minutes=deliver_mins))
            req = _coerce_req(t.cast(TJSON, body.get("req", {})))
            meta = t.cast(TJSON, body.get("meta", {})) if isinstance(body.get("meta", {}), dict) else {}
            tix = self.app.st.create_ticket(
                actor=actor,
                client_id=client_id,
                valid_until=valid_until,
                deliver_by=deliver_by,
                token_symbol=token_symbol,
                max_total=max_total,
                units=units,
                req=req,
                meta=meta,
            )
            return json_response(self, 201, {"ticket": dataclasses.asdict(tix) | {"req": dataclasses.asdict(tix.req)}})
        if method == "POST" and len(parts) == 3 and parts[0] == "tickets" and parts[2] == "close":
            body = parse_json_body(self, cfg.max_body_bytes)
            reason = _must_nonempty_str(body.get("reason", "manual"), what="reason", max_len=140)
            tix = self.app.st.close_ticket(actor=actor, ticket_id=parts[1], reason=reason)
            return json_response(self, 200, {"ticket": dataclasses.asdict(tix) | {"req": dataclasses.asdict(tix.req)}})

        # matcher
        if method == "GET" and parts == ["matches", "suggest"]:
            qp = qparams(self.path)
            limit = int(qp.get("limit", "50"))
            picks = self.app.matcher.suggest_matches(limit=limit)
            return json_response(self, 200, {"suggestions": picks})
        if method == "POST" and parts == ["matches", "execute"]:
            body = parse_json_body(self, cfg.max_body_bytes)
            limit = _safe_int(body.get("limit", 1), what="limit")
            if limit < 1 or limit > self.app.cfg.match_batch_limit:
                raise BadRequest("limit out of range")
            out = self.app.matcher.execute_best(actor=actor, limit=limit)
            items = [dataclasses.asdict(m) for m in out]
            return json_response(self, 200, {"matches": items})
        if method == "GET" and parts == ["matches"]:
            qp = qparams(self.path)
            state = qp.get("state")
            limit = int(qp.get("limit", "200"))
            ms = self.app.st.list_matches(state=state, limit=limit)
            return json_response(self, 200, {"items": [dataclasses.asdict(m) for m in ms]})
        if method == "GET" and len(parts) == 2 and parts[0] == "matches":
            m = self.app.st.get_match(parts[1])
            return json_response(self, 200, {"match": dataclasses.asdict(m)})
        if method == "POST" and len(parts) == 3 and parts[0] == "matches" and parts[2] == "deliver":
            body = parse_json_body(self, cfg.max_body_bytes)
            blob_b64 = _must_nonempty_str(body.get("result_b64u", ""), what="result_b64u", max_len=4_000_000)
            meta = t.cast(TJSON, body.get("meta", {})) if isinstance(body.get("meta", {}), dict) else {}
            result = b64u_decode(blob_b64)
            m = self.app.st.deliver_result(actor=actor, match_id=parts[1], result_blob=result, meta=meta)
            return json_response(self, 200, {"match": dataclasses.asdict(m)})
        if method == "POST" and len(parts) == 3 and parts[0] == "matches" and parts[2] == "finalize":
            body = parse_json_body(self, cfg.max_body_bytes)
            fee_bps = _safe_int(body.get("fee_bps", 247), what="fee_bps")
            treasury = _must_nonempty_str(body.get("treasury", "treasury"), what="treasury", max_len=120)
            m = self.app.st.finalize_match(actor=actor, match_id=parts[1], fee_bps=fee_bps, treasury_owner=treasury)
            return json_response(self, 200, {"match": dataclasses.asdict(m)})

        # audit
        if method == "GET" and parts == ["audit"]:
            qp = qparams(self.path)
            limit = int(qp.get("limit", "200"))
            items = self.app.st.list_audit(limit=limit)
            return json_response(self, 200, {"items": items})

        raise NotFound("no such route")

    def do_GET(self) -> None:
        try:
            self._dispatch()
        except RateLimited as e:
            json_response(self, 429, problem(429, str(e)))
        except Unauthorized as e:
            json_response(self, 401, problem(401, str(e)))
        except NotFound as e:
            json_response(self, 404, problem(404, str(e)))
        except BadRequest as e:
            json_response(self, 400, problem(400, str(e)))
        except Conflict as e:
            json_response(self, 409, problem(409, str(e)))
        except Integrity as e:
            json_response(self, 422, problem(422, str(e)))
        except Exception as e:
            LOG.exception("unhandled")
            json_response(self, 500, problem(500, "internal error", detail=str(e)))

    def do_POST(self) -> None:
        return self.do_GET()


class ThreadedHTTPServer(http.server.ThreadingHTTPServer):
    def __init__(self, addr: tuple[str, int], handler_cls: type[Handler], app: App):
        super().__init__(addr, handler_cls)
        self.app = app


def run_server(cfg: AppConfig) -> None:
    configure_logging(cfg.log_level)
    app = App(cfg)
    Handler.app = app

    srv = ThreadedHTTPServer((cfg.http_host, cfg.http_port), Handler, app)
    LOG.info("listening on http://%s:%d", cfg.http_host, cfg.http_port)
    LOG.info("db=%s", cfg.db_path)
    LOG.info("admin_token=%s", cfg.admin_token)

    stop = threading.Event()

    def _sig(*_: t.Any) -> None:
        stop.set()

    try:
        signal.signal(signal.SIGINT, _sig)
        signal.signal(signal.SIGTERM, _sig)
    except Exception:
        pass

    try:
        while not stop.is_set():
            srv.handle_request()
    finally:
        try:
            srv.server_close()
        except Exception:
            pass
        app.close()


def cli_suggest(cfg: AppConfig, args: argparse.Namespace) -> None:
    configure_logging(cfg.log_level)
    app = App(cfg)
    try:
        picks = app.matcher.suggest_matches(limit=args.limit)
        print(json_dumps({"suggestions": picks}, pretty=True))
    finally:
        app.close()


def cli_execute(cfg: AppConfig, args: argparse.Namespace) -> None:
    configure_logging(cfg.log_level)
    app = App(cfg)
    try:
        actor = args.actor or "cli"
        out = app.matcher.execute_best(actor=actor, limit=args.limit)
        print(json_dumps({"matches": [dataclasses.asdict(m) for m in out]}, pretty=True))
    finally:
        app.close()

def cli_mint_token(cfg: AppConfig, args: argparse.Namespace) -> None:
    configure_logging(cfg.log_level)
    app = App(cfg)
    try:
        tok = app.issue_actor_token(args.actor_id, ttl_s=args.ttl_s)
        print(json_dumps({"token": tok, "actor_id": args.actor_id, "ttl_s": args.ttl_s}, pretty=True))
    finally:
        app.close()

def build_cli() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="PowerRouter_ZZ", description="Compute matching platform (CLI + HTTP API)")
    sp = p.add_subparsers(dest="cmd", required=True)

    s = sp.add_parser("serve", help="run HTTP API server")
    s.set_defaults(fn=lambda cfg, a: run_server(cfg))

    s = sp.add_parser("suggest", help="suggest best matches")
    s.add_argument("--limit", type=int, default=50)
    s.set_defaults(fn=cli_suggest)

    s = sp.add_parser("execute", help="execute N best matches")
    s.add_argument("--limit", type=int, default=1)
    s.add_argument("--actor", type=str, default="cli")
    s.set_defaults(fn=cli_execute)

    s = sp.add_parser("mint-actor-token", help="mint a bearer token for actor auth")
    s.add_argument("actor_id", type=str)
    s.add_argument("--ttl-s", type=int, default=6 * 3600)
    s.set_defaults(fn=cli_mint_token)

    return p

def main(argv: list[str] | None = None) -> int:
    if argv is None:
        argv = list(os.sys.argv[1:])
    cfg = AppConfig.load()
    p = build_cli()
    args = p.parse_args(argv)
    try:
        fn = getattr(args, "fn")
        fn(cfg, args)
        return 0
    except AppError as e:
        print(json_dumps({"error": str(e), "ts": iso_utc()}, pretty=True))
        return 2
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
