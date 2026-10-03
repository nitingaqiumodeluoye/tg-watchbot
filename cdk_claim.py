"""Server-side CDK claimer for cdk.linux.do give-away links.

Design notes
------------
The claim needs three independent things, each with its own lifetime:

* ``cf_clearance``            -- bound to (egress IP + browser fingerprint + UA).
  Cloudflare issues it per hostname, so the ``linux.do`` clearance the monitor
  already caches is *not* valid for ``cdk.linux.do``. It is fetched fresh from
  the local cf_bypass service, which drives a real browser and solves the
  challenge; the returned ``user_agent`` MUST be replayed verbatim or the
  clearance is rejected.
* ``linux_do_cdk_session_id`` -- the OAuth session cookie for cdk.linux.do.
  Not IP-bound: it was obtained once by hand (see oauth notes in the repo) and
  is reused here until the API answers 401.
* hCaptcha token             -- short-lived (~120s), produced by a captcha
  service. The token is bound to the UA the solver used, which is why the
  request is made with the *solver's* UA when it differs.

Everything is synchronous because the caller (run_monitor) already runs the
claim in a worker thread; keeping it sync avoids entangling the monitor's
asyncio loop with a 30-120s captcha poll.
"""

from __future__ import annotations

import json
import logging
import os
import re
import sqlite3
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlencode, urlparse

import httpx

logger = logging.getLogger("tg-watchbot.cdk_claim")

try:  # curl_cffi gives us a browser-like TLS fingerprint for the direct calls
    from curl_cffi import requests as curl_requests
except Exception:  # pragma: no cover - dependency is in requirements.txt
    curl_requests = None


CDK_BASE = "https://cdk.linux.do"
CDK_RECEIVE_HOST = "cdk.linux.do"
HCAPTCHA_SITEKEY = "a37e0976-7144-4ed8-8344-4f5c6e203b3a"
HCAPTCHA_INVISIBLE = True

# The exact path shape we claim from: https://cdk.linux.do/receive/<project_id>
CDK_RECEIVE_PATH_RE = re.compile(
    r"^/receive/([0-9a-fA-F-]{16,64})/?$",
)

DEFAULT_CLIENT_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:143.0) Gecko/20100101 Firefox/143.0"
)

# curl_cffi selects the TLS/JA4 fingerprint on its own; the User-Agent header does
# not influence it. Cloudflare binds cf_clearance to that fingerprint, so the
# preset -- not the cookie and not the UA -- decides whether a request passes.
# Measured on cdk.linux.do against one freshly minted clearance with the bypass UA
# (Firefox 144): firefox133 reached the origin 3/3 while firefox135, firefox144 and
# the bare firefox alias were challenged 0/3 each. curl_cffi's firefox144 is the
# preset this code used to hard-code, which is why every CDK request was 403.
DEFAULT_IMPERSONATE = "firefox133"
_IMPERSONATE_FALLBACKS = ("firefox133", "firefox135", "firefox144", "firefox")
_active_impersonate = ""
_preset_supported_cache: dict[str, bool] = {}


def _preset_supported(name: str) -> bool:
    """Whether curl_cffi knows this impersonate target (cached, no network)."""
    if not name:
        return False
    if name not in _preset_supported_cache:
        try:
            if curl_requests is None:
                raise RuntimeError("curl_cffi missing")
            curl_requests.Session(impersonate=name).close()
            _preset_supported_cache[name] = True
        except Exception:
            _preset_supported_cache[name] = False
    return _preset_supported_cache[name]


def _impersonate_candidates() -> tuple[str, ...]:
    """Presets to try, best-known first; ``CDK_IMPERSONATE`` overrides them all.

    Unsupported names are dropped rather than attempted, so a typo in the
    environment cannot turn into a stream of failed CDK requests.
    """
    order: list[str] = []
    for name in (
        os.getenv("CDK_IMPERSONATE", "").strip(),
        _active_impersonate,
        *_IMPERSONATE_FALLBACKS,
    ):
        if name and name not in order and _preset_supported(name):
            order.append(name)
    return tuple(order) or (DEFAULT_IMPERSONATE,)


def active_impersonate() -> str:
    """The preset to use: the one Cloudflare accepted last, else the default."""
    return _active_impersonate or _impersonate_candidates()[0]


def remember_impersonate(name: str) -> None:
    """Pin the preset that just worked so claims keep using it."""
    global _active_impersonate
    if name and name != _active_impersonate:
        _active_impersonate = name
        logger.info("cdk impersonate preset accepted: %s", name)


@dataclass
class ClaimResult:
    """Outcome of a claim attempt, with enough detail to explain a failure."""

    ok: bool = False
    content: str = ""
    error: str = ""
    project_id: str = ""
    project_name: str = ""
    reason: str = ""
    detail: str = ""
    elapsed_ms: int = 0
    already_received: bool = False
    received_elsewhere: bool = False
    start_time: float = 0.0
    waited_seconds: float = 0.0
    attempts: int = 0
    trust_level: int = 0
    min_trust_level: int = 0
    score: int = 0
    price: int = 0
    payment_url: str = ""
    payment_trade_no: str = ""

    def summary(self) -> str:
        if self.ok:
            return f"领取成功 project={self.project_id} chars={len(self.content)}"
        return f"领取失败 project={self.project_id} reason={self.reason} error={self.error}"


# --------------------------------------------------------------------------- #
# Configuration
# --------------------------------------------------------------------------- #

def _env_bool(name: str, default: bool = False) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def cdk_claim_enabled() -> bool:
    """Global switch: automatic claiming is opt-in (``CDK_CLAIM_ENABLED=1``)."""
    return _env_bool("CDK_CLAIM_ENABLED", False)


def cdk_claim_dry_run() -> bool:
    """Solve captcha and resolve the project, but never POST /receive."""
    return _env_bool("CDK_CLAIM_DRY_RUN", False)


def cdk_session_file() -> str:
    return os.getenv("CDK_SESSION_FILE", "/app/cdk_session.json").strip()


def cdk_captcha_provider() -> str:
    return (os.getenv("CDK_CAPTCHA_PROVIDER", "") or os.getenv("CAPTCHA_PROVIDER", "yescaptcha")).strip()


def cdk_claim_timeout_seconds() -> int:
    return max(10, int(os.getenv("CDK_CLAIM_TIMEOUT_SECONDS", "45")))


def cdk_captcha_timeout_seconds() -> int:
    return max(30, int(os.getenv("CDK_CAPTCHA_TIMEOUT_SECONDS", "180")))


def cdk_cf_retry_limit() -> int:
    """Maximum clearance refresh retries per claim phase after a CF challenge."""
    try:
        return max(0, min(3, int(os.getenv("CDK_CF_RETRY_LIMIT", "1"))))
    except ValueError:
        return 1


def cdk_start_wait_max_seconds() -> float:
    """How long a claim may sit waiting for the project's start_time.

    A give-away post is usually published a little before it opens; waiting for
    the opening bell wins the race far more often than firing early. Beyond
    this ceiling the claim gives up waiting and reports back instead of holding
    a background task (and a captcha token) for hours.
    """
    return max(0.0, float(os.getenv("CDK_START_WAIT_MAX_SECONDS", "600")))


def cdk_early_solve_seconds() -> float:
    """Lead time before start_time at which captcha solving begins.

    hCaptcha tokens live ~120s, so solving too early wastes them; solving at the
    bell wastes the first seconds of the race. Default 20s.
    """
    return max(0.0, float(os.getenv("CDK_EARLY_SOLVE_SECONDS", "20")))


def cdk_retry_window_seconds() -> float:
    """How long the retry loop keeps trying after the opening bell."""
    return max(0.0, float(os.getenv("CDK_RETRY_WINDOW_SECONDS", "30")))


def cdk_stock_grace_seconds() -> float:
    """How long after the bell an "out of stock" reply is still worth retrying.

    The stock counter can lag the opening bell by a second or two, so a claim
    fired exactly at start_time may legitimately see "no stock" and succeed on
    the next tick. Long after the bell the same reply is final, and retrying it
    only buys more captcha tokens. Default 15s.
    """
    return max(0.0, float(os.getenv("CDK_STOCK_GRACE_SECONDS", "15")))


def retry_deadline(start_ts: float) -> float:
    """Absolute epoch time at which the retry loop gives up.

    With a start_time the window runs from the opening bell, so a claim that
    waited 9 minutes still gets its full retry allowance *after* the bell.
    """
    now = time.time()
    anchor = start_ts if start_ts and start_ts > now - 5 else now
    return anchor + cdk_retry_window_seconds()


# --------------------------------------------------------------------------- #
# Session store (linux_do_cdk_session_id)
# --------------------------------------------------------------------------- #

@dataclass
class CdkSession:
    session_id: str = ""
    user_agent: str = DEFAULT_CLIENT_UA
    saved_at: float = 0.0
    source: str = ""

    @property
    def ok(self) -> bool:
        return bool(self.session_id)


_session_cache: CdkSession | None = None


def load_cdk_session(*, refresh: bool = False) -> CdkSession:
    """Read the OAuth session cookie, cached in memory between claims.

    The cookie outlives a single monitor tick (it is a *login* session, not a
    per-request token), so it is read once and kept. ``refresh=True`` re-reads
    it, which is what the caller does after a 401 so a freshly synced cookie
    takes effect without restarting the process.
    """
    global _session_cache
    if _session_cache is not None and _session_cache.ok and not refresh:
        return _session_cache

    path = cdk_session_file()
    data: dict[str, Any] = {}
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh) or {}
    except FileNotFoundError:
        data = {}
    except Exception as exc:  # malformed file should not take the bot down
        data = {"__error": str(exc)}

    raw_cookies = data.get("cookies")
    if isinstance(raw_cookies, list):
        raw_cookies = {
            str(c.get("name")): str(c.get("value"))
            for c in raw_cookies
            if isinstance(c, dict) and c.get("name")
        }
    if not isinstance(raw_cookies, dict):
        raw_cookies = {}

    session_id = str(
        data.get("linux_do_cdk_session_id")
        or raw_cookies.get("linux_do_cdk_session_id")
        or ""
    ).strip()
    ua = str(data.get("user_agent") or data.get("ua") or DEFAULT_CLIENT_UA).strip()
    saved_at = float(data.get("saved_at") or 0)

    session = CdkSession(session_id=session_id, user_agent=ua, saved_at=saved_at, source=path)
    if session_id:
        _session_cache = session
    return session


def save_cdk_session(session_id: str, *, user_agent: str = "", source: str = "sync") -> CdkSession:
    """Persist a session cookie (used by the local sync helper / tests)."""
    global _session_cache
    path = cdk_session_file()
    payload = {
        "linux_do_cdk_session_id": session_id,
        "user_agent": user_agent or DEFAULT_CLIENT_UA,
        "saved_at": time.time(),
        "source": source,
    }
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, ensure_ascii=False, indent=1)
    _session_cache = CdkSession(
        session_id=session_id,
        user_agent=payload["user_agent"],
        saved_at=payload["saved_at"],
        source=path,
    )
    return _session_cache


# --------------------------------------------------------------------------- #
# cf_clearance via the local bypass service
# --------------------------------------------------------------------------- #

def cf_bypass_url() -> str:
    return (
        os.getenv("CDK_CF_BYPASS_URL")
        or os.getenv("CF_BYPASS_URL")
        or "http://127.0.0.1:18001"
    ).rstrip("/")


def fetch_cdk_clearance(
    *, force: bool = False, timeout: int = 150, target_url: str = ""
) -> tuple[dict[str, str], str]:
    """Ask the bypass browser to solve a challenge and return a cookie jar.

    ``target_url`` is the page the browser actually loads, and it matters:
    Cloudflare applies challenge rules per path, so a clearance minted on
    /dashboard is not necessarily accepted for /api/v1/projects/<id>. Minting on
    the request a claim will make keeps the two consistent.

    Returns ``(cookies, user_agent)``. The UA must be replayed on every later
    request: a clearance issued to one UA is rejected when presented with
    another (verified: same cookie + default UA -> 403 challenge).
    """
    base = cf_bypass_url()
    # /dashboard remains the fallback: it is the page the bypass browser is
    # known to warm up on, and an expired project can answer 404 there.
    params = {"url": str(target_url or "").strip() or f"{CDK_BASE}/dashboard"}
    if force:
        params["force"] = "true"
    endpoint = f"{base}/cookies?{urlencode(params)}"
    with httpx.Client(timeout=timeout, trust_env=False) as client:
        resp = client.get(endpoint, follow_redirects=True)
        resp.raise_for_status()
        data = resp.json()
    cookies = data.get("cookies") or {}
    ua = str(data.get("user_agent") or "").strip()
    if not isinstance(cookies, dict):
        cookies = {}
    normalized = {str(k): str(v) for k, v in cookies.items()}
    return normalized, ua


_clearance_cache: dict[str, Any] = {"cookies": {}, "user_agent": ""}

# Probe bookkeeping. The clearance has no TTL: like the monitor's cf session it is
# kept until Cloudflare stops accepting it. ``verified`` records the outcome of
# the last validation, so a caller can tell "we hold a cookie" apart from
# "Cloudflare accepted it". ``project_id`` is the most recent give-away and is
# what the periodic probe targets, because the project API -- not the page -- is
# the request a claim has to pass.
_probe_state: dict[str, Any] = {
    "last_probe_at": 0.0, "url": "", "verified": False, "project_id": "",
}
_probe_url_loaded = False


def _probe_state_db() -> str:
    return os.getenv("CDK_STATE_DB", "/app/tg-watchbot.sqlite3").strip()


def _load_persisted_probe_state() -> dict[str, str]:
    """Read back the last give-away probe target so a restart is not blind.

    Kept in the monitor's sqlite file because that is the one path docker-compose
    mounts; anything written inside the image is lost on the next rebuild, and an
    empty memory sends the probe to /dashboard, which Cloudflare samples.
    """
    try:
        with sqlite3.connect(f"file:{_probe_state_db()}?mode=ro", uri=True) as conn:
            rows = conn.execute(
                "SELECT key, value FROM cdk_probe_state "
                "WHERE key IN ('probe_url', 'probe_project_id')"
            ).fetchall()
        return {str(k): str(v) for k, v in rows if v}
    except Exception:
        return {}


def _persist_probe_state(**values: str) -> None:
    values = {k: v for k, v in values.items() if v}
    if not values:
        return
    try:
        with sqlite3.connect(_probe_state_db()) as conn:
            conn.execute(
                "CREATE TABLE IF NOT EXISTS cdk_probe_state ("
                "key TEXT PRIMARY KEY, value TEXT NOT NULL)"
            )
            conn.executemany(
                "INSERT INTO cdk_probe_state(key, value) VALUES(?, ?) "
                "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                list(values.items()),
            )
            conn.commit()
    except Exception as exc:
        logger.debug("cdk probe state persist failed: %s", type(exc).__name__)


def cdk_clearance_probe_seconds() -> float:
    """How often the cached clearance is probed. Default 10 minutes."""
    return max(60.0, float(os.getenv("CDK_CLEARANCE_PROBE_SECONDS", "600")))


def remember_cdk_link(link: str) -> None:
    """Remember the most recent give-away, which becomes the probe target.

    The project API is what a claim needs to reach, so that is what gets probed;
    the page URL is kept as a fallback for when no project id is known.
    """
    project_id = project_id_from_link(link)
    if project_id:
        _probe_state["project_id"] = project_id
        _probe_state["url"] = f"{CDK_BASE}/receive/{project_id}"
        _persist_probe_state(
            probe_project_id=project_id, probe_url=_probe_state["url"]
        )


def claim_probe_url(project_id: str) -> str:
    """The URL a clearance must pass for ``project_id``.

    This is deliberately the API a claim calls, not the /receive page: a page
    probe can answer 200 while the project API returns `cf-mitigated: challenge`,
    so probing the page reported a warm clearance that then failed mid-claim.
    """
    return f"{CDK_BASE}/api/v1/projects/{project_id}" if project_id else ""


def clearance_probe_url() -> str:
    """The URL the periodic probe validates the cached clearance against.

    Prefers the project API of the most recent give-away, because that is the
    request a claim actually has to pass; probing the /receive page reported
    healthy while the API answered `cf-mitigated: challenge`, which is how a
    rejected clearance still looked warm. Falls back to the give-away page, then
    to the warmup page, so the first probe after a restart still has a target.
    """
    global _probe_url_loaded
    if not _probe_url_loaded:
        _probe_url_loaded = True
        if not _probe_state.get("url") or not _probe_state.get("project_id"):
            saved = _load_persisted_probe_state()
            if not _probe_state.get("url"):
                _probe_state["url"] = saved.get("probe_url", "")
            if not _probe_state.get("project_id"):
                _probe_state["project_id"] = saved.get("probe_project_id", "")
        if not _probe_state.get("project_id"):
            # State written before the probe moved to the API only holds the page
            # URL, so recover the id from it instead of falling back to /dashboard.
            _probe_state["project_id"] = project_id_from_link(
                str(_probe_state.get("url") or "")
            )
    api = claim_probe_url(str(_probe_state.get("project_id") or ""))
    if api:
        return api
    return str(_probe_state.get("url") or "") or f"{CDK_BASE}/dashboard"


def verify_clearance(
    cookies: dict[str, str],
    user_agent: str,
    session_id: str = "",
    url: str = "",
    impersonate: str = "",
) -> bool:
    """Check a candidate clearance still passes cdk.linux.do.

    The bypass service hands back whatever session it currently holds, and a
    replacement clearance arrives with a new User-Agent (observed: FF143 ->
    FF140 across two consecutive warmups). A clearance is only valid for the UA
    that solved the challenge, so a stale cache 403s every request until
    something forces a refresh.

    The probe target matters as much as the probe itself: pointing it at a path
    Cloudflare samples would discard a perfectly healthy clearance and pay for a
    new browser challenge. Hence the give-away link, not user-info.

    ``impersonate`` is the curl_cffi TLS preset; it is the single strongest
    factor, so callers walk the candidates via :func:`probe_clearance` instead of
    giving up after one rejected fingerprint.
    """
    target = url or clearance_probe_url()
    preset = impersonate or active_impersonate()
    if not cookies.get("cf_clearance") or not user_agent:
        logger.warning("cdk clearance validation failed url=%s reason=missing_credentials", target)
        return False
    jar = dict(cookies)
    if session_id:
        jar["linux_do_cdk_session_id"] = session_id
    client = None
    try:
        client = _new_client(user_agent, jar, impersonate=preset)
        resp = client.get(
            target,
            headers=_browser_headers(target, user_agent),
            timeout=20,
        )
        mitigated = str(resp.headers.get("cf-mitigated", "")).strip().lower()
        challenged = mitigated == "challenge" or _challenge_like(resp)
        # Cloudflare accepted the session whenever the request reached the
        # origin: 2xx does, and so do 404 (expired give-away) and 401 (the app
        # answered "未登录", which is the tell-tale of a cleared challenge with no
        # session cookie attached). 403/429 without origin headers prove nothing,
        # so they must never count as healthy.
        verified = not challenged and (
            200 <= resp.status_code < 300 or resp.status_code in (401, 404)
        )
        if verified:
            remember_impersonate(preset)
        logger.log(
            logging.INFO if verified else logging.WARNING,
            "cdk clearance validation url=%s status=%s cf_mitigated=%s challenge=%s "
            "verified=%s impersonate=%s",
            target, resp.status_code, mitigated or "none", challenged, verified, preset,
        )
        return verified
    except Exception as exc:
        logger.warning(
            "cdk clearance validation failed url=%s reason=request_error "
            "impersonate=%s error_type=%s",
            target, preset, type(exc).__name__,
        )
        return False
    finally:
        if client is not None:
            try:
                client.close()
            except Exception:
                pass


def probe_clearance(
    cookies: dict[str, str], user_agent: str, session_id: str = "", url: str = ""
) -> bool:
    """Validate a clearance against every fingerprint candidate in turn.

    The cookie and the User-Agent can both be flawless and still be rejected when
    the TLS fingerprint is wrong, so a single rejected preset says nothing about
    the session's health. Costs nothing extra: these are direct API requests, not
    browser challenges.
    """
    for preset in _impersonate_candidates():
        if verify_clearance(cookies, user_agent, session_id, url, impersonate=preset):
            return True
    return False


def _mint_clearance(
    session_id: str, probe_url: str, *, force: bool
) -> tuple[dict[str, str], str, bool]:
    """Ask the bypass browser for a session and validate it against ``probe_url``.

    The browser loads the very URL the session will be used for, so the challenge
    is solved on the same path (and by the same rule set) as the claim. ``force``
    makes the bypass drop its own cached browser session first, and that is what
    "get a *new* clearance" means: without it the service hands back the very
    session that was just rejected, and the retry repeats the same 403.
    """
    try:
        cookies, ua = fetch_cdk_clearance(force=force, target_url=probe_url)
    except Exception as exc:
        logger.warning(
            "cdk clearance mint failed force=%s error_type=%s", force, type(exc).__name__
        )
        return {}, "", False
    if not cookies.get("cf_clearance") or not ua:
        logger.warning(
            "cdk clearance mint incomplete force=%s cookies=%s ua=%s",
            force, len(cookies), bool(ua),
        )
        return {}, "", False
    return cookies, ua, probe_clearance(cookies, ua, session_id, probe_url)


def cached_clearance(
    session_id: str = "", probe_url: str = "", *, force: bool = False
) -> tuple[dict[str, str], str]:
    """Return a cdk.linux.do clearance, minting a fresh one when the old fails.

    Deliberately has no TTL, mirroring the monitor's cf session: minting one costs
    43-72s of headless browser time, and replacing a clearance the origin is still
    accepting only feeds the rate limiting that breaks it. Instead the cached
    session is re-used as-is until a validation says Cloudflare stopped accepting
    it -- and at that point the refresh must be *forced*, because the bypass still
    holds that same rejected session in its own cache.

    ``force=True`` skips the cached session entirely, which is what a caller does
    after a request was challenged: mint a new clearance and use it immediately.
    """
    target = probe_url or clearance_probe_url()
    now = time.time()
    cached = _clearance_cache
    if not force and cached.get("cookies") and cached["cookies"].get("cf_clearance"):
        if now - float(_probe_state.get("last_probe_at") or 0.0) < cdk_clearance_probe_seconds():
            return cached["cookies"], cached["user_agent"]
        if probe_clearance(cached["cookies"], cached["user_agent"], session_id, target):
            _probe_state.update({"last_probe_at": now, "verified": True})
            return cached["cookies"], cached["user_agent"]
        logger.info("cdk clearance no longer accepted, minting a fresh one url=%s", target)
        drop_clearance_cache()
        force = True

    # A cold cache may still be served from the bypass's own session store, which
    # costs no browser time; only a rejected session has to be forced.
    # A mint that fails validation must not be trusted for the whole probe
    # window, so it is retried with a forced refresh before being accepted.
    unvalidated: tuple[dict[str, str], str] = ({}, "")
    for use_force in ((True,) if force else (False, True)):
        cookies, ua, verified = _mint_clearance(session_id, target, force=use_force)
        if not cookies:
            continue
        unvalidated = (cookies, ua)
        if verified:
            _clearance_cache.update({"cookies": cookies, "user_agent": ua})
            _probe_state.update({"last_probe_at": now, "verified": True})
            return cookies, ua
        logger.warning(
            "cdk clearance minted but not validated url=%s force=%s", target, use_force
        )

    if unvalidated[0]:
        # Cloudflare never confirmed the session, but it exists: hand it over so
        # the claim can try and report the real error, while last_probe_at stays
        # at zero and the health probe keeps calling it unverified.
        _clearance_cache.update({"cookies": unvalidated[0], "user_agent": unvalidated[1]})
        _probe_state.update({"last_probe_at": 0.0, "verified": False})
        return unvalidated

    drop_clearance_cache()
    raise RuntimeError("CDK clearance unavailable: bypass returned no usable session")


def refresh_clearance_if_stale(*, force: bool = False) -> dict[str, Any]:
    """Probe (or mint) the clearance outside of a claim, for the timer job.

    Keeping the cache warm is the point: a give-away posted after a long idle
    stretch would otherwise pay 43-72s of browser time before its first request,
    which a first-come-first-served grab cannot afford.
    """
    if force:
        drop_clearance_cache()
    session_id = ""
    try:
        session = load_cdk_session()
        session_id = session.session_id if session.ok else ""
    except Exception:
        pass
    try:
        cookies, ua = cached_clearance(session_id=session_id)
    except Exception as exc:
        return {
            "ok": False,
            "url": clearance_probe_url(),
            "error": f"{type(exc).__name__}: {exc}"[:200],
        }
    # ``ok`` means Cloudflare accepted the session, not merely that a cookie was
    # handed back; a mint that failed validation must not be reported as healthy.
    return {
        "ok": bool(cookies.get("cf_clearance") and ua and _probe_state.get("verified")),
        "url": clearance_probe_url(),
        "verified_at": float(_probe_state.get("last_probe_at") or 0.0),
        "ua": ua,
    }


def drop_clearance_cache() -> None:
    _clearance_cache.update({"cookies": {}, "user_agent": ""})
    _probe_state.update({"last_probe_at": 0.0, "verified": False})


# --------------------------------------------------------------------------- #
# Project / link parsing
# --------------------------------------------------------------------------- #

def project_id_from_link(link: str) -> str:
    """Extract the project id from a /receive/<id> give-away link."""
    try:
        path = urlparse(link).path or ""
    except Exception:
        return ""
    m = CDK_RECEIVE_PATH_RE.match(path)
    return m.group(1) if m else ""


def solve_captcha(site_referer: str, provider: str = "") -> tuple[str, str]:
    """Solve hCaptcha, returning ``(token, solver_user_agent)``.

    Providers are the same set the local grabber supports. Each one is
    implemented inline so the server needs no extra dependency beyond httpx.
    """
    provider = (provider or cdk_captcha_provider()).strip().lower()
    deadline = time.time() + cdk_captcha_timeout_seconds()

    if provider == "yescaptcha":
        return _solve_yescaptcha(site_referer, deadline)
    if provider == "captcharun":
        return _solve_captcharun(site_referer, deadline)
    if provider == "nocaptcha":
        return _solve_nocaptcha(site_referer, deadline)
    if provider == "jfbym":
        return _solve_jfbym(site_referer, deadline)
    if provider == "local":
        return _solve_local(site_referer, deadline)
    raise RuntimeError(f"unknown captcha provider: {provider!r}")


def _poll(task, deadline: float, interval: float, is_success, is_failure, extract):
    """Shared poll loop: keeps each provider implementation tiny."""
    while time.time() < deadline:
        time.sleep(interval)
        data = task()
        if is_success(data):
            return extract(data)
        if is_failure(data):
            raise RuntimeError(str(data)[:200])
    raise TimeoutError("captcha solve timed out")


def _solve_yescaptcha(site_referer: str, deadline: float) -> tuple[str, str]:
    key = os.getenv("YESCAPTCHA_API_KEY", "").strip()
    if not key:
        raise RuntimeError("YESCAPTCHA_API_KEY not configured")
    base = os.getenv("YESCAPTCHA_BASE", "https://api.yescaptcha.com").rstrip("/")
    with httpx.Client(timeout=30, trust_env=False) as client:
        resp = client.post(
            f"{base}/createTask",
            json={
                "clientKey": key,
                "task": {
                    "type": "HCaptchaTaskProxyless",
                    "websiteURL": site_referer,
                    "websiteKey": HCAPTCHA_SITEKEY,
                    "isInvisible": HCAPTCHA_INVISIBLE,
                },
            },
        )
        data = resp.json()
        if data.get("errorId", 0) != 0:
            raise RuntimeError(f"yescaptcha create: {data.get('errorDescription')}")
        task_id = data["taskId"]

        def poll():
            r = client.post(f"{base}/getTaskResult", json={"clientKey": key, "taskId": task_id})
            return r.json()

        def extract(d):
            sol = d.get("solution") or {}
            token = sol.get("gRecaptchaResponse") or sol.get("token") or ""
            ua = sol.get("userAgent") or DEFAULT_CLIENT_UA
            return token, ua

        return _poll(
            poll, deadline, 3.0,
            lambda d: d.get("status") == "ready",
            lambda d: d.get("errorId", 0) != 0,
            extract,
        )


def _solve_captcharun(site_referer: str, deadline: float) -> tuple[str, str]:
    key = os.getenv("CAPTCHA_RUN_API_KEY", "").strip()
    if not key:
        raise RuntimeError("CAPTCHA_RUN_API_KEY not configured")
    base = os.getenv("CAPTCHA_RUN_BASE", "https://api.captcha-run.com/v2/tasks").rstrip("/")
    headers = {"Authorization": f"Bearer {key}"}
    with httpx.Client(timeout=30, trust_env=False) as client:
        resp = client.post(
            base,
            json={
                "captchaType": "HCaptcha",
                "siteKey": HCAPTCHA_SITEKEY,
                "siteReferer": site_referer,
                "isInvisible": HCAPTCHA_INVISIBLE,
                "fallbackToActualUA": True,
            },
            headers=headers,
        )
        task_id = resp.json()["taskId"]

        def poll():
            return client.get(f"{base}/{task_id}", headers=headers).json()

        def extract(d):
            r = d.get("response") or {}
            return r.get("gRecaptchaResponse", ""), r.get("userAgent") or DEFAULT_CLIENT_UA

        return _poll(
            poll, deadline, 5.0,
            lambda d: d.get("status") == "Success",
            lambda d: d.get("status") == "Fail",
            extract,
        )


def _solve_nocaptcha(site_referer: str, deadline: float) -> tuple[str, str]:
    token = os.getenv("NOCAPTCHA_USER_TOKEN", "").strip()
    if not token:
        raise RuntimeError("NOCAPTCHA_USER_TOKEN not configured")
    url = os.getenv("NOCAPTCHA_API_URL", "https://api.nocaptcha.io/api/v1/recognition/hcaptcha")
    with httpx.Client(timeout=min(120, cdk_captcha_timeout_seconds()), trust_env=False) as client:
        resp = client.post(
            url,
            json={
                "sitekey": HCAPTCHA_SITEKEY,
                "referer": site_referer,
                "invisible": HCAPTCHA_INVISIBLE,
            },
            headers={"User-Token": token},
        )
        data = resp.json()
    if data.get("status") != 1:
        raise RuntimeError(f"nocaptcha: {data.get('msg')}")
    return data["data"]["generated_pass_UUID"], DEFAULT_CLIENT_UA


def _solve_jfbym(site_referer: str, deadline: float) -> tuple[str, str]:
    token = os.getenv("JFBYM_API_KEY", "").strip()
    if not token:
        raise RuntimeError("JFBYM_API_KEY not configured")
    base = os.getenv("JFBYM_BASE", "http://api.jfbym.com/api/YmServer").rstrip("/")
    with httpx.Client(timeout=30, trust_env=False) as client:
        resp = client.post(
            f"{base}/captcha/hcaptcha",
            json={
                "token": token,
                "type": "20111",
                "sitekey": HCAPTCHA_SITEKEY,
                "pageurl": site_referer,
                "invisible": HCAPTCHA_INVISIBLE,
            },
        )
        data = resp.json()
        if data.get("code") != 10000:
            raise RuntimeError(f"jfbym: {data.get('msg')}")
        raw = data.get("data", "")
        parsed = json.loads(raw) if isinstance(raw, str) and raw.strip().startswith("{") else {}
        result = parsed.get("data") or raw
    return str(result), DEFAULT_CLIENT_UA


def _solve_local(site_referer: str, deadline: float) -> tuple[str, str]:
    """Local hcaptcha-challenger API server (noCaptcha-compatible shape)."""
    url = os.getenv("LOCAL_API_URL", "").strip()
    if not url:
        raise RuntimeError("LOCAL_API_URL not configured")
    headers = {}
    if os.getenv("LOCAL_API_TOKEN"):
        headers["User-Token"] = os.environ["LOCAL_API_TOKEN"]
    with httpx.Client(timeout=min(240, cdk_captcha_timeout_seconds()), trust_env=False) as client:
        resp = client.post(
            url,
            json={
                "sitekey": HCAPTCHA_SITEKEY,
                "referer": site_referer,
                "invisible": HCAPTCHA_INVISIBLE,
            },
            headers=headers,
        )
        data = resp.json()
    if data.get("status") != 1:
        raise RuntimeError(f"local solver: {data.get('msg')}")
    return data["data"]["generated_pass_UUID"], DEFAULT_CLIENT_UA


# --------------------------------------------------------------------------- #
# CDK API
# --------------------------------------------------------------------------- #

def _browser_headers(referer: str, ua: str) -> dict[str, str]:
    return {
        "accept": "application/json, text/plain, */*",
        "accept-language": "zh-CN,zh;q=0.9,en;q=0.8",
        "referer": referer,
        "user-agent": ua,
        "sec-fetch-dest": "empty",
        "sec-fetch-mode": "cors",
        "sec-fetch-site": "same-origin",
    }


def _new_client(user_agent: str, cookies: dict[str, str], impersonate: str = ""):
    """curl_cffi session with a browser TLS fingerprint and cookies preloaded.

    The fingerprint has to match the browser that solved the challenge, and the
    UA header has to be the one that browser reported; both are replayed here.
    """
    if curl_requests is None:
        raise RuntimeError("curl_cffi is required for cdk claims")
    client = curl_requests.Session(impersonate=impersonate or active_impersonate())
    client.headers["User-Agent"] = user_agent
    for name, value in cookies.items():
        client.cookies.set(name, value, domain=".linux.do")
    return client


def _parse_body(resp) -> dict[str, Any]:
    try:
        data = resp.json()
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def _challenge_like(resp) -> bool:
    body = (getattr(resp, "text", "") or "")[:4000]
    return resp.status_code in (403, 429) and (
        "cf_chl_opt" in body or "Just a moment" in body or "challenge-platform" in body
    )


def get_project_info(project_id: str, client) -> dict[str, Any]:
    """Fetch the project document; used to skip already-claimed projects."""
    url = f"{CDK_BASE}/api/v1/projects/{project_id}"
    resp = client.get(
        url,
        headers=_browser_headers(f"{CDK_BASE}/receive/{project_id}", client.headers.get("User-Agent", DEFAULT_CLIENT_UA)),
        timeout=cdk_claim_timeout_seconds(),
    )
    if _challenge_like(resp):
        raise PermissionError("cloudflare")
    data = _parse_body(resp)
    if data.get("error_msg"):
        raise RuntimeError(str(data["error_msg"]))
    result = data.get("data", {})
    return result if isinstance(result, dict) else {}


def parse_start_time(value: Any) -> float:
    """Parse a CDK start_time (ISO-8601) into an epoch timestamp; 0 on failure."""
    raw = str(value or "").strip()
    if not raw:
        return 0.0
    text = raw.replace("Z", "+00:00")
    try:
        dt = datetime.fromisoformat(text)
    except ValueError:
        return 0.0
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.timestamp()


def get_user_info(client) -> dict[str, Any]:
    """Fetch the signed-in account (trust_level / score), for eligibility."""
    resp = client.get(
        f"{CDK_BASE}/api/v1/oauth/user-info",
        headers=_browser_headers(f"{CDK_BASE}/", client.headers.get("User-Agent", DEFAULT_CLIENT_UA)),
        timeout=cdk_claim_timeout_seconds(),
    )
    if _challenge_like(resp):
        raise PermissionError("cloudflare")
    data = _parse_body(resp)
    if data.get("error_msg"):
        raise RuntimeError(str(data["error_msg"]))
    result = data.get("data", {})
    return result if isinstance(result, dict) else {}


@dataclass
class Precheck:
    """Free eligibility verdict computed before any captcha credit is spent.

    ``waits_for_start`` separates the two kinds of "0 stock": a project that
    has not opened yet legitimately reports no stock, while one whose start_time
    has passed and still reports 0 really is gone. Only the latter is hopeless.
    """

    go: bool = True
    reason: str = ""
    detail: str = ""
    start_ts: float = 0.0
    end_ts: float = 0.0
    waits_for_start: bool = False
    wait_seconds: float = 0.0
    # ``None`` means "user-info could not be read", which is not the same as a
    # real zero and must not trip the trust-level/score gates.
    trust_level: int | None = None
    min_trust_level: int = 0
    score: int | None = None
    price: int = 0
    available: int | None = None


# NOTE: the precheck rejects a hopeless project before the captcha is ever
# solved, so a rejection there never reaches the retry loop. This list exists
# only to document which verdicts are final, and is asserted in the tests.
PRECHECK_HARD_STOP = {
    "already_received",
    "ended",
    "completed",
    "trust_level",
    "insufficient_score",
    "out_of_stock",
    "not_found",
}


def precheck_eligibility(info: dict[str, Any], user: dict[str, Any]) -> Precheck:
    """Decide whether a claim is worth attempting, using only free API calls.

    Everything here comes from two GETs (project + user-info), so the verdict
    costs nothing. It exists to avoid paying for a captcha token on a project
    that is already claimed, expired, above our trust level, or genuinely out
    of stock -- and to report *why* instead of a generic failure.
    """
    p = Precheck()
    p.start_ts = parse_start_time(info.get("start_time"))
    p.end_ts = parse_start_time(info.get("end_time"))
    trust = user.get("trust_level")
    p.trust_level = int(trust) if trust is not None else None
    p.min_trust_level = int(info.get("minimum_trust_level") or 0)
    score = user.get("score")
    p.score = int(score) if score is not None else None
    try:
        p.price = int(float(info.get("price") or 0))
    except (TypeError, ValueError):
        p.price = 0
    available = info.get("available_items_count")
    p.available = int(available) if isinstance(available, int) else None

    now = time.time()

    # A start_time in the future is the one case where 0 stock is expected.
    if p.start_ts > now:
        wait = p.start_ts - now
        if wait <= cdk_start_wait_max_seconds():
            p.waits_for_start = True
            p.wait_seconds = wait

    if info.get("is_received"):
        return _reject(p, "already_received", "该项目此前已领取过")
    if p.end_ts and now > p.end_ts:
        return _reject(p, "ended", f"项目已过期（end_time={info.get('end_time')}）")
    # ``is_completed`` means the give-away is over (all items handed out), which
    # is observable independently of the clock. ``status`` is deliberately not
    # consulted: its values could not be verified against a live project.
    if info.get("is_completed"):
        return _reject(p, "completed", "项目已完成（is_completed）")
    if p.min_trust_level and p.trust_level is not None and p.trust_level < p.min_trust_level:
        return _reject(
            p, "trust_level",
            f"社区等级不足：需要 L{p.min_trust_level}，当前 L{p.trust_level}",
        )
    if p.price > 0 and p.score is not None and p.score < p.price:
        return _reject(p, "insufficient_score", f"积分不足：需要 {p.price}，当前 {p.score}")
    if p.available is not None and p.available <= 0 and not p.waits_for_start:
        return _reject(p, "out_of_stock", "库存为 0 且已过开始时间")
    return p


def _reject(p: Precheck, reason: str, detail: str) -> Precheck:
    p.go = False
    p.reason = reason
    p.detail = detail
    return p


def post_receive(project_id: str, captcha_token: str, client) -> dict[str, Any]:
    """POST /api/v1/projects/{id}/receive with the hCaptcha token."""
    url = f"{CDK_BASE}/api/v1/projects/{project_id}/receive"
    resp = client.post(
        url,
        json={"captcha_token": captcha_token},
        headers=_browser_headers(f"{CDK_BASE}/receive/{project_id}", client.headers.get("User-Agent", DEFAULT_CLIENT_UA)),
        timeout=cdk_claim_timeout_seconds(),
    )
    if _challenge_like(resp):
        raise PermissionError("cloudflare")
    data = _parse_body(resp)
    if resp.status_code >= 400 and not data:
        raise RuntimeError(f"HTTP {resp.status_code}: {(resp.text or '')[:160]}")
    return data


# --------------------------------------------------------------------------- #
# Orchestration
# --------------------------------------------------------------------------- #

def confirm_received(result: ClaimResult, session) -> None:
    """Re-read the project after a failed claim: the code may be ours anyway.

    A Cloudflare challenge or a timeout can hit the *response* of a POST the
    server had already committed. The project document still carries
    ``is_received``/``received_content``, and a first-come-first-served code can
    never be regenerated, so a failure is not accepted until the project has
    been read back.
    """
    if result.ok or not result.project_id:
        return
    probe_target = claim_probe_url(result.project_id)
    info: dict[str, Any] = {}
    for attempt_force in (False, True):
        try:
            cookies, ua = cached_clearance(
                session_id=session.session_id, probe_url=probe_target, force=attempt_force
            )
            jar = dict(cookies)
            jar["linux_do_cdk_session_id"] = session.session_id
            client = _new_client(ua, jar)
            info = get_project_info(result.project_id, client)
            break
        except Exception as exc:
            if attempt_force:
                logger.info("cdk confirm skipped project=%s: %s", result.project_id, exc)
                return
            # The read-back is the last chance to recover a code that was
            # actually issued, so a challenged first read buys a fresh clearance.
            logger.info(
                "cdk confirm challenged, retrying with a new clearance project=%s",
                result.project_id,
            )
    if info.get("is_received") and info.get("received_content"):
        logger.info("cdk claim confirmed despite reported failure project=%s", result.project_id)
        result.ok = True
        result.already_received = False
        result.content = str(info["received_content"])
        result.reason = "confirmed_after_failure"
        result.error = ""


def claim_link(link: str, *, dry_run: bool = False, refresh_session: bool = False) -> ClaimResult:
    """Claim the give-away at ``link`` end to end.

    Steps: resolve project id -> ensure clearance + session -> skip when the
    project is already claimed -> solve hCaptcha -> POST /receive. Any failure
    is returned as a ClaimResult rather than raised, so a monitor tick never
    dies because a give-away expired.
    """
    started = time.time()
    result = ClaimResult(project_id=project_id_from_link(link))
    if not result.project_id:
        result.reason = "bad_link"
        result.error = f"cannot parse project id from {link!r}"
        return result

    session = load_cdk_session(refresh=refresh_session)
    if not session.ok:
        result.reason = "no_session"
        result.error = f"no linux_do_cdk_session_id at {cdk_session_file()}"
        return result

    probe_target = claim_probe_url(result.project_id)
    remember_cdk_link(link)
    try:
        cookies, clear_ua = cached_clearance(
            session_id=session.session_id, probe_url=probe_target
        )
    except Exception as exc:
        result.reason = "clearance_failed"
        result.error = f"cf bypass: {exc}"[:300]
        return result
    if "cf_clearance" not in cookies:
        result.reason = "clearance_failed"
        result.error = "cf_clearance missing from bypass response"
        return result

    # The clearance is bound to the UA that solved the challenge, and is bound
    # harder than the session cookie: replaying the session's own UA against a
    # bypass-issued clearance is an immediate 403 (verified on the server).
    user_agent = clear_ua or session.user_agent
    jar = dict(cookies)
    jar["linux_do_cdk_session_id"] = session.session_id

    client = _new_client(user_agent, jar)

    def renew_client() -> None:
        """Replace the clearance with a brand new one and rebuild the client.

        A challenged request means Cloudflare stopped accepting the session in
        hand, and the bypass service still holds that very session in its own
        cache, so the refresh has to be forced. Raises when no new session is
        issued, which the caller reports as a Cloudflare failure.
        """
        nonlocal client, user_agent, jar
        cookies, clear_ua = cached_clearance(
            session_id=session.session_id, probe_url=probe_target, force=True
        )
        if "cf_clearance" not in cookies:
            raise PermissionError("cloudflare")
        user_agent = clear_ua or user_agent
        jar = dict(cookies)
        jar["linux_do_cdk_session_id"] = session.session_id
        client = _new_client(user_agent, jar)

    try:
        # A project query can be challenged even when the cached clearance
        # recently passed the /receive probe. Refresh once and retry the query
        # before abandoning the claim.
        project_cf_retries = 0
        while True:
            try:
                info = get_project_info(result.project_id, client)
                break
            except PermissionError:
                if project_cf_retries >= cdk_cf_retry_limit():
                    raise
                project_cf_retries += 1
                logger.info(
                    "cdk project query challenged, refreshing clearance and retrying "
                    "project=%s retry=%d",
                    result.project_id, project_cf_retries,
                )
                renew_client()
        result.project_name = str(info.get("name") or "")
        if info.get("is_received"):
            result.already_received = True
            result.ok = True
            result.content = str(info.get("received_content") or "")
            result.reason = "already_received"
            result.elapsed_ms = int((time.time() - started) * 1000)
            return result

        # Free eligibility gate before any captcha credit is spent. A project we
        # can never claim (claimed already, expired, above our trust level, or
        # genuinely sold out) is reported instead of being retried for 30s.
        user: dict[str, Any] = {}
        try:
            user = get_user_info(client)
        except PermissionError:
            # user-info is challenged intermittently on its own, while the
            # project endpoint keeps answering with the very same clearance.
            # It gates only the trust-level/score checks, so a challenge here
            # must not forfeit a claimable give-away: refresh the clearance,
            # retry once, then carry on with those two gates unknown.
            logger.info("cdk user-info challenged, refreshing clearance and retrying")
            try:
                renew_client()
                user = get_user_info(client)
            except Exception as exc:
                logger.info("cdk user-info unavailable (%s), trust/score gates skipped", exc)
                user = {}
        except Exception as exc:
            # A missing user-info must not block a claim: the precheck simply
            # cannot evaluate the trust-level/score gates without it.
            logger.info("cdk user-info failed (%s), trust/score gates skipped", exc)
            user = {}
        pre = precheck_eligibility(info, user)
        result.start_time = pre.start_ts
        # -1 marks "unknown" (user-info unavailable); these are diagnostic only
        # and are never persisted or compared again.
        result.trust_level = pre.trust_level if pre.trust_level is not None else -1
        result.min_trust_level = pre.min_trust_level
        result.score = pre.score if pre.score is not None else -1
        result.price = pre.price
        if not pre.go:
            result.reason = pre.reason
            result.error = pre.detail
            return result

        # A give-away usually opens at a posted start_time. Wait for the bell
        # (bounded) rather than burning the attempt an hour early; the wait is
        # reported so the follow-up message can explain the delay.
        start_ts = pre.start_ts
        if pre.waits_for_start:
            # Solve just before the bell so the token is still fresh.
            pre_solve_at = start_ts - cdk_early_solve_seconds()
            if pre_solve_at > time.time():
                time.sleep(pre_solve_at - time.time())
                result.waited_seconds = time.time() - started

        if dry_run:
            result.reason = "dry_run"
            result.error = "dry run: skipped captcha + receive"
            result.elapsed_ms = int((time.time() - started) * 1000)
            return result

        # Retry loop: right after the start_time the project can still report
        # no stock for a second or two, or reject a stale captcha token. Each
        # pass solves a fresh token and retries until the window closes. A CF
        # challenge refreshes the clearance and rebuilds the client before the
        # next pass, but is limited separately from normal business retries.
        attempt = 0
        receive_cf_retries = 0
        deadline = retry_deadline(start_ts)
        while True:
            attempt += 1
            result.attempts = attempt
            token, _solver_ua = solve_captcha(f"{CDK_BASE}/receive/{result.project_id}")
            if not token:
                result.reason = "captcha_failed"
                result.error = "captcha solver returned an empty token"
                break

            try:
                data = post_receive(result.project_id, token, client)
            except PermissionError:
                if receive_cf_retries >= cdk_cf_retry_limit():
                    raise
                receive_cf_retries += 1
                logger.info(
                    "cdk receive challenged, refreshing clearance and retrying "
                    "project=%s retry=%d",
                    result.project_id, receive_cf_retries,
                )
                renew_client()
                # The next loop iteration solves a fresh hCaptcha token too.
                continue
            error_msg = str(data.get("error_msg") or "").strip()
            payload = data.get("data") or {}
            if not isinstance(payload, dict):
                payload = {}
            # Paid giveaways are a normal business result, not a successful
            # claim: return the payment URL so the operator can complete it.
            if payload.get("require_payment"):
                result.payment_url = str(payload.get("pay_url") or "")
                result.payment_trade_no = str(payload.get("trade_no") or "")
                result.reason = "payment_required"
                result.error = "需要支付 LDC 后领取" if result.payment_url else "需要支付 LDC，但接口未返回支付链接"
                break
            if not error_msg:
                result.ok = True
                result.content = str(payload.get("itemContent") or "")
                result.reason = "claimed"
                break

            if "已领取" in error_msg or "重复" in error_msg:
                result.already_received = True
                result.reason = "refused"
                result.error = error_msg
                break

            # Split the retry decision in two, because the two families cost
            # very different amounts. A timing or rate-limit complaint clears on
            # its own, so retrying is free money. "Out of stock" is only worth
            # retrying in the short window where the counter lags the bell;
            # afterwards it is final and every retry buys another captcha.
            retryable = any(
                k in error_msg
                for k in ("未开始", "还没开始", "未到", "频繁", "验证", "captcha")
            )
            if not retryable and any(k in error_msg for k in ("库存", "抢光", "领取人数")):
                within_grace = bool(start_ts) and time.time() < start_ts + cdk_stock_grace_seconds()
                if not within_grace:
                    result.reason = "out_of_stock"
                    result.error = error_msg
                    break
                retryable = True
            if not retryable or time.time() >= deadline:
                result.reason = "refused"
                result.error = error_msg
                break
            time.sleep(1.0)
    except PermissionError:
        # Clearance died mid-flight: drop it so the next attempt re-warms.
        drop_clearance_cache()
        result.reason = "cloudflare"
        result.error = "cloudflare challenged the claim request"
    except Exception as exc:
        result.reason = result.reason or "error"
        result.error = f"{type(exc).__name__}: {exc}"[:300]
    finally:
        result.elapsed_ms = int((time.time() - started) * 1000)

    # A failure is not final until the project has been read back: the code may
    # have been handed out before the response was lost.
    if not result.ok and result.reason != "payment_required":
        confirm_received(result, session)
    return result


def claim_links(links: list[str], *, dry_run: bool = False) -> list[ClaimResult]:
    """Claim several links in order, stopping at the first success."""
    results: list[ClaimResult] = []
    for link in links or []:
        res = claim_link(link, dry_run=dry_run)
        results.append(res)
        if res.ok:
            break
    return results
