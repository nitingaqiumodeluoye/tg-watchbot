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
import os
import re
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlencode, urlparse

import httpx

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


def fetch_cdk_clearance(*, force: bool = False, timeout: int = 150) -> tuple[dict[str, str], str]:
    """Ask the bypass browser for a cdk.linux.do cookie jar.

    Returns ``(cookies, user_agent)``. The UA must be replayed on every later
    request: a clearance issued to one UA is rejected when presented with
    another (verified: same cookie + default UA -> 403 challenge).
    """
    base = cf_bypass_url()
    params = {"url": f"{CDK_BASE}/dashboard"}
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


_clearance_cache: dict[str, Any] = {"cookies": {}, "user_agent": "", "expires_at": 0.0}


def verify_clearance(cookies: dict[str, str], user_agent: str, session_id: str = "") -> bool:
    """Check a candidate clearance actually passes cdk.linux.do.

    The bypass service hands back whatever session it currently holds, and a
    replacement clearance arrives with a new User-Agent (observed: FF143 ->
    FF140 across two consecutive warmups). A clearance is only valid for the
    UA that solved the challenge, so caches built before a warmup go stale and
    every request 403s until something forces a refresh. Verifying once here
    costs ~200ms and removes that whole failure mode.
    """
    if not cookies.get("cf_clearance"):
        return False
    jar = dict(cookies)
    if session_id:
        jar["linux_do_cdk_session_id"] = session_id
    try:
        client = _new_client(user_agent, jar)
        resp = client.get(
            f"{CDK_BASE}/api/v1/oauth/user-info",
            headers=_browser_headers(f"{CDK_BASE}/", user_agent),
            timeout=20,
        )
    except Exception:
        return False
    return not _challenge_like(resp) and resp.status_code < 500


def cached_clearance(ttl: float = 300.0, session_id: str = "") -> tuple[dict[str, str], str]:
    """Return a cdk.linux.do clearance that is known to work.

    Cached entries are re-verified before reuse, and a failed verification
    escalates to ``force=True`` (which tells the bypass service to drop its own
    cached session first). That escalation matters: without it the bypass keeps
    replaying a session Cloudflare has already stopped accepting.
    """
    now = time.time()
    cached = _clearance_cache
    if (
        cached["cookies"]
        and "cf_clearance" in cached["cookies"]
        and cached["expires_at"] > now
        and verify_clearance(cached["cookies"], cached["user_agent"], session_id)
    ):
        return cached["cookies"], cached["user_agent"]

    for force in (False, True):
        cookies, ua = fetch_cdk_clearance(force=force)
        if not cookies.get("cf_clearance") or not ua:
            continue
        if verify_clearance(cookies, ua, session_id):
            _clearance_cache.update(
                {"cookies": cookies, "user_agent": ua, "expires_at": now + ttl}
            )
            return cookies, ua
    # Nothing verified: hand back the last attempt so the caller's error path
    # reports the real response instead of a synthetic "missing cookie".
    return cookies, ua


def drop_clearance_cache() -> None:
    _clearance_cache.update({"cookies": {}, "user_agent": "", "expires_at": 0.0})


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


def _new_client(user_agent: str, cookies: dict[str, str]):
    """curl_cffi session (browser TLS) with cookies preloaded."""
    if curl_requests is None:
        raise RuntimeError("curl_cffi is required for cdk claims")
    # firefox143 matches the bypass browser that minted the clearance.
    try:
        client = curl_requests.Session(impersonate="firefox144")
    except Exception:
        client = curl_requests.Session(impersonate="firefox133")
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
    trust_level: int = 0
    min_trust_level: int = 0
    score: int = 0
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
    p.trust_level = int(user.get("trust_level") or 0)
    p.min_trust_level = int(info.get("minimum_trust_level") or 0)
    p.score = int(user.get("score") or 0)
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
    if p.min_trust_level and p.trust_level < p.min_trust_level:
        return _reject(
            p, "trust_level",
            f"社区等级不足：需要 L{p.min_trust_level}，当前 L{p.trust_level}",
        )
    if p.price > 0 and p.score < p.price:
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

    try:
        cookies, clear_ua = cached_clearance(session_id=session.session_id)
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
    try:
        info = get_project_info(result.project_id, client)
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
        try:
            user = get_user_info(client)
        except PermissionError:
            raise
        except Exception as exc:
            # A missing user-info must not block a claim: the precheck simply
            # cannot evaluate the trust-level/score gates without it.
            user = {}
        pre = precheck_eligibility(info, user)
        result.start_time = pre.start_ts
        result.trust_level = pre.trust_level
        result.min_trust_level = pre.min_trust_level
        result.score = pre.score
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
        # pass solves a fresh token and retries until the window closes.
        attempt = 0
        deadline = retry_deadline(start_ts)
        while True:
            attempt += 1
            result.attempts = attempt
            token, _solver_ua = solve_captcha(f"{CDK_BASE}/receive/{result.project_id}")
            if not token:
                result.reason = "captcha_failed"
                result.error = "captcha solver returned an empty token"
                return result

            data = post_receive(result.project_id, token, client)
            error_msg = str(data.get("error_msg") or "").strip()
            if not error_msg:
                payload = data.get("data") or {}
                result.ok = True
                result.content = str(payload.get("itemContent") or "")
                result.reason = "claimed"
                return result

            if "已领取" in error_msg or "重复" in error_msg:
                result.already_received = True
                result.reason = "refused"
                result.error = error_msg
                return result

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
                    return result
                retryable = True
            if not retryable or time.time() >= deadline:
                result.reason = "refused"
                result.error = error_msg
                return result
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
