"""Unit tests for the cf_warmup_url helper family.

Run:  python -m unittest tests.test_cf_warmup -v
"""
from __future__ import annotations

import os
import time
import unittest
from urllib.parse import parse_qs, urlparse

import app


class _FakeResponse:
    def __init__(self, payload=None, status=200):
        self._payload = payload
        self.status_code = status

    def raise_for_status(self):
        if self.status_code >= 400:
            raise RuntimeError(f"HTTP {self.status_code}")

    def json(self):
        return self._payload


class _FakeAsyncClient:
    """Records requests and serves canned cookie payloads keyed by target URL."""

    instances: list = []
    payloads: dict = {}

    def __init__(self, *, timeout=None, trust_env=None, **kwargs):
        self.timeout = timeout
        self.calls: list = []
        _FakeAsyncClient.instances.append(self)

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False

    def _target(self, url: str) -> str:
        return (parse_qs(urlparse(url).query).get("url") or [""])[0]

    async def get(self, url, **kwargs):
        self.calls.append(("GET", url))
        payload = _FakeAsyncClient.payloads.get(self._target(url))
        if payload is None:
            return _FakeResponse(status=500)
        return _FakeResponse(payload)

    async def post(self, url, **kwargs):
        self.calls.append(("POST", url))
        return _FakeResponse(payload={})


class CfWarmupUrlTests(unittest.TestCase):
    def test_explicit_warmup_url_wins(self):
        monitor = {
            "name": "福利",
            "url": "https://linux.do/c/welfare/36.json",
            "cf_bypass": True,
            "cf_warmup_url": "https://linux.do/",
        }
        self.assertEqual(app.cf_warmup_url(monitor), "https://linux.do/")

    def test_defaults_to_origin_root(self):
        monitor = {
            "name": "福利",
            "url": "https://linux.do/c/welfare/36.json",
            "cf_bypass": True,
        }
        self.assertEqual(app.cf_warmup_url(monitor), "https://linux.do/")

    def test_keeps_port_in_origin(self):
        monitor = {
            "name": "x",
            "url": "https://example.com:8443/api/list.json",
            "cf_bypass": True,
        }
        self.assertEqual(app.cf_warmup_url(monitor), "https://example.com:8443/")

    def test_nested_path_root_is_not_the_monitored_url(self):
        monitor = {
            "name": "x",
            "url": "https://example.com/deep/path/data.json",
            "cf_bypass": True,
        }
        self.assertNotEqual(app.cf_warmup_url(monitor), monitor["url"])

    def test_without_cf_bypass_returns_target(self):
        monitor = {"name": "x", "url": "https://example.com/a.json"}
        self.assertEqual(app.cf_warmup_url(monitor), "https://example.com/a.json")

    def test_relative_or_invalid_url_is_passed_through(self):
        monitor = {"name": "x", "url": "not-a-url", "cf_bypass": True}
        self.assertEqual(app.cf_warmup_url(monitor), "not-a-url")

    def test_empty_url(self):
        self.assertEqual(app.cf_warmup_url({"name": "x", "cf_bypass": True}), "")


class CfWarmupCookieNamesTests(unittest.TestCase):
    def test_default_is_cf_clearance(self):
        self.assertEqual(app.cf_warmup_cookie_names({}), {"cf_clearance"})

    def test_comma_and_space_separated_string(self):
        names = app.cf_warmup_cookie_names({"cf_warmup_cookie_names": "cf_clearance, _t  foo"})
        self.assertEqual(names, {"cf_clearance", "_t", "foo"})

    def test_sequence_input(self):
        names = app.cf_warmup_cookie_names({"cf_warmup_cookie_names": ["a", " b ", ""]})
        self.assertEqual(names, {"a", "b"})

    def test_blank_string_falls_back_to_default(self):
        self.assertEqual(app.cf_warmup_cookie_names({"cf_warmup_cookie_names": "   "}), {"cf_clearance"})


class CfWarmupSatisfiedTests(unittest.TestCase):
    def test_true_when_cf_clearance_present(self):
        monitor = {}
        self.assertTrue(app.cf_warmup_satisfied(monitor, {"_cfuvid": "1", "cf_clearance": "2"}))

    def test_false_without_cf_clearance(self):
        monitor = {}
        self.assertFalse(app.cf_warmup_satisfied(monitor, {"_cfuvid": "1", "_t": "2"}))

    def test_any_configured_name_satisfies(self):
        monitor = {"cf_warmup_cookie_names": "cf_clearance,_forum_session"}
        self.assertTrue(app.cf_warmup_satisfied(monitor, {"_forum_session": "x"}))
        self.assertFalse(app.cf_warmup_satisfied(monitor, {"_cfuvid": "x"}))

    def test_empty_jar_never_satisfies_default(self):
        self.assertFalse(app.cf_warmup_satisfied({}, {}))


class PreservedKeysTests(unittest.TestCase):
    def test_warmup_keys_are_preserved_on_panel_save(self):
        for key in ("cf_warmup_url", "cf_warmup_cookie_names"):
            self.assertIn(key, app.PRESERVED_MONITOR_FORM_KEYS, key)

    def test_preserver_keeps_warmup_url(self):
        old = {"cf_warmup_url": "https://linux.do/", "cf_warmup_cookie_names": "cf_clearance"}
        new = {"name": "福利"}
        merged = app.preserve_monitor_form_hidden_fields(new, old)
        self.assertEqual(merged["cf_warmup_url"], "https://linux.do/")
        self.assertEqual(merged["cf_warmup_cookie_names"], "cf_clearance")

    def test_preserver_does_not_override_explicit_new_value(self):
        old = {"cf_warmup_url": "https://linux.do/"}
        new = {"cf_warmup_url": "https://linux.do/latest"}
        merged = app.preserve_monitor_form_hidden_fields(new, old)
        self.assertEqual(merged["cf_warmup_url"], "https://linux.do/latest")


class CacheTtlTests(unittest.TestCase):
    """The default is 'no expiry': keep using the clearance until it dies."""

    def test_default_ttl_is_zero(self):
        self.assertEqual(app.cf_cache_ttl_seconds({"name": "x"}), 0)

    def test_default_expires_at_is_none(self):
        self.assertIsNone(app.cf_session_expires_at({"name": "x"}))

    def test_explicit_ttl_produces_future_expiry(self):
        monitor = {"name": "x", "cf_cookie_ttl_seconds": 120}
        self.assertEqual(app.cf_cache_ttl_seconds(monitor), 120)
        expires_at = app.cf_session_expires_at(monitor)
        self.assertIsNotNone(expires_at)
        self.assertGreater(expires_at, time.time())

    def test_negative_ttl_is_floored_to_zero(self):
        monitor = {"name": "x", "cf_cookie_ttl_seconds": -5}
        self.assertEqual(app.cf_cache_ttl_seconds(monitor), 0)
        self.assertIsNone(app.cf_session_expires_at(monitor))

    def test_expired_explicit_ttl_session_is_dropped(self):
        monitor = {"name": "x", "url": "https://linux.do/a.json"}
        app.cf_cookie_cache[app.cf_cache_key(monitor)] = {
            "cookies": {"_cfuvid": "v"},
            "user_agent": "UA/1",
            "expires_at": time.time() - 1,
        }
        try:
            self.assertIsNone(app.cf_cached_session(monitor))
        finally:
            app.cf_cookie_cache.clear()

    def test_no_expiry_session_survives_far_future(self):
        monitor = {"name": "x", "url": "https://linux.do/a.json"}
        app.cf_cookie_cache[app.cf_cache_key(monitor)] = {
            "cookies": {"_cfuvid": "v"},
            "user_agent": "UA/1",
            "expires_at": None,
        }
        try:
            self.assertIsNotNone(app.cf_cached_session(monitor))
        finally:
            app.cf_cookie_cache.clear()


class RefreshCfCookieCacheTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        app.cf_cookie_cache.clear()
        app.cf_cookie_refresh_locks.clear()
        _FakeAsyncClient.instances = []
        _FakeAsyncClient.payloads = {}
        self._orig_client = app.httpx.AsyncClient
        app.httpx.AsyncClient = _FakeAsyncClient

    def tearDown(self):
        app.httpx.AsyncClient = self._orig_client
        app.cf_cookie_cache.clear()
        app.cf_cookie_refresh_locks.clear()

    @staticmethod
    def _monitor(**extra):
        monitor = {
            "name": "Linux.do 福利",
            "url": "https://linux.do/c/welfare/36.json",
            "cf_bypass": True,
            "cf_bypass_url": "http://127.0.0.1:18001",
        }
        monitor.update(extra)
        return monitor

    @staticmethod
    def _jar(*names):
        return {"cookies": {n: "v" for n in names}, "user_agent": "UA/1"}

    @staticmethod
    def _all_calls(method=None):
        """Every request across every client (each attempt builds its own client)."""
        calls = [c for inst in _FakeAsyncClient.instances for c in inst.calls]
        if method:
            calls = [c for c in calls if c[0] == method]
        return calls

    def _get_targets(self):
        targets = []
        for _, url in self._all_calls("GET"):
            targets.append((parse_qs(urlparse(url).query).get("url") or [""])[0])
        return targets

    async def test_warmup_clearance_short_circuits_target(self):
        # Warmup page yields a clearance -> the monitored URL must not be hit.
        _FakeAsyncClient.payloads = {
            "https://linux.do/": self._jar("_cfuvid", "cf_clearance"),
        }
        monitor = self._monitor()
        self.assertTrue(await app.refresh_cf_cookie_cache(None, monitor))
        self.assertEqual(self._get_targets(), ["https://linux.do/"])
        self.assertEqual(app.cf_cached_session(monitor)["cookies"]["cf_clearance"], "v")

    async def test_falls_back_to_target_when_warmup_lacks_clearance(self):
        _FakeAsyncClient.payloads = {
            "https://linux.do/": self._jar("_cfuvid"),
            "https://linux.do/c/welfare/36.json": self._jar("_cfuvid", "_t"),
        }
        monitor = self._monitor()
        self.assertTrue(await app.refresh_cf_cookie_cache(None, monitor))
        # Warmup first, then the monitored URL as the fallback.
        self.assertEqual(
            self._get_targets(),
            ["https://linux.do/", "https://linux.do/c/welfare/36.json"],
        )
        self.assertIn("_t", app.cf_cached_session(monitor)["cookies"])

    async def test_force_invalidates_bypass_cache_exactly_once(self):
        _FakeAsyncClient.payloads = {
            "https://linux.do/": self._jar("_cfuvid"),
            "https://linux.do/c/welfare/36.json": self._jar("_cfuvid", "_t"),
        }
        await app.refresh_cf_cookie_cache(None, self._monitor(), force=True)
        posts = [url for _, url in self._all_calls("POST")]
        # Regression: a per-attempt invalidate would wipe the warmup result.
        self.assertEqual(len(posts), 1)
        self.assertTrue(posts[0].endswith("/cache/invalidate?url=https%3A%2F%2Flinux.do%2F") or
                        "/cache/invalidate" in posts[0])
        # The invalidate must happen before any cookie request.
        self.assertEqual(self._all_calls()[0][0], "POST")

    async def test_force_passes_force_param_to_warmup_request(self):
        # With no TTL the bypass service would otherwise hand back the dead
        # clearance forever, so the warmup request must ask for a fresh solve.
        _FakeAsyncClient.payloads = {"https://linux.do/": self._jar("cf_clearance")}
        await app.refresh_cf_cookie_cache(None, self._monitor(), force=True)
        get_params = [
            parse_qs(urlparse(url).query) for method, url in self._all_calls("GET")
        ]
        self.assertTrue(get_params)
        self.assertEqual(get_params[0].get("force"), ["true"])

    async def test_non_force_request_does_not_pass_force_param(self):
        _FakeAsyncClient.payloads = {"https://linux.do/": self._jar("cf_clearance")}
        await app.refresh_cf_cookie_cache(None, self._monitor())
        get_params = [parse_qs(urlparse(url).query) for _, url in self._all_calls("GET")]
        self.assertNotIn("force", get_params[0])

    async def test_uses_refresh_timeout_not_monitor_timeout(self):
        _FakeAsyncClient.payloads = {"https://linux.do/": self._jar("cf_clearance")}
        # cf_refresh_timeout_seconds defaults to 150s, far above the 20s monitor timeout.
        await app.refresh_cf_cookie_cache(None, self._monitor())
        self.assertTrue(_FakeAsyncClient.instances)
        for instance in _FakeAsyncClient.instances:
            self.assertEqual(instance.timeout, app.cf_refresh_timeout_seconds(self._monitor()))

    async def test_existing_cache_short_circuits_without_http(self):
        monitor = self._monitor()
        app.cf_cookie_cache[app.cf_cache_key(monitor)] = {
            "cookies": {"_cfuvid": "v"},
            "user_agent": "UA/1",
            "expires_at": time.time() + 600,
        }
        self.assertTrue(await app.refresh_cf_cookie_cache(None, monitor))
        self.assertEqual(_FakeAsyncClient.instances, [])

    async def test_session_with_no_expiry_is_served_from_cache(self):
        # Default: expires_at is None -> kept until a fetch proves it dead.
        monitor = self._monitor()
        app.cf_cookie_cache[app.cf_cache_key(monitor)] = {
            "cookies": {"_cfuvid": "v", "cf_clearance": "c"},
            "user_agent": "UA/1",
            "expires_at": None,
        }
        session = app.cf_cached_session(monitor)
        self.assertIsNotNone(session)
        self.assertTrue(await app.refresh_cf_cookie_cache(None, monitor))
        self.assertEqual(_FakeAsyncClient.instances, [])

    async def test_custom_warmup_url_is_used(self):
        _FakeAsyncClient.payloads = {
            "https://linux.do/latest": self._jar("cf_clearance"),
        }
        monitor = self._monitor(cf_warmup_url="https://linux.do/latest")
        self.assertTrue(await app.refresh_cf_cookie_cache(None, monitor))
        self.assertEqual(self._get_targets(), ["https://linux.do/latest"])

    async def test_custom_required_cookie_names(self):
        # Only _forum_session counts as a good warmup here.
        _FakeAsyncClient.payloads = {
            "https://linux.do/": self._jar("_cfuvid", "_forum_session"),
        }
        monitor = self._monitor(cf_warmup_cookie_names="_forum_session")
        self.assertTrue(await app.refresh_cf_cookie_cache(None, monitor))
        self.assertEqual(self._get_targets(), ["https://linux.do/"])

    async def test_total_failure_returns_false(self):
        _FakeAsyncClient.payloads = {}  # every request 500s
        self.assertFalse(await app.refresh_cf_cookie_cache(None, self._monitor()))

    async def test_error_on_warmup_still_tries_target(self):
        # Warmup raises (e.g. timeout) -> must still fall through to the target.
        _FakeAsyncClient.payloads = {
            "https://linux.do/c/welfare/36.json": self._jar("_cfuvid", "_t"),
        }
        monitor = self._monitor()
        self.assertTrue(await app.refresh_cf_cookie_cache(None, monitor))
        self.assertEqual(self._get_targets(), [
            "https://linux.do/",
            "https://linux.do/c/welfare/36.json",
        ])


class InvalidatedSessionRetryTests(unittest.IsolatedAsyncioTestCase):
    """A clearance that Cloudflare rejects must be dropped and re-warmed."""

    def setUp(self):
        app.cf_cookie_cache.clear()
        app.cf_cookie_refresh_locks.clear()
        _FakeAsyncClient.instances = []
        _FakeAsyncClient.payloads = {}
        self._orig_client = app.httpx.AsyncClient
        app.httpx.AsyncClient = _FakeAsyncClient

    def tearDown(self):
        app.httpx.AsyncClient = self._orig_client
        app.cf_cookie_cache.clear()
        app.cf_cookie_refresh_locks.clear()

    def _monitor(self):
        return {
            "name": "Linux.do 福利",
            "url": "https://linux.do/c/welfare/36.json",
            "cf_bypass": True,
            "cf_bypass_url": "http://127.0.0.1:18001",
        }

    def _seed_dead_session(self, monitor):
        app.cf_cookie_cache[app.cf_cache_key(monitor)] = {
            "cookies": {"_cfuvid": "stale", "cf_clearance": "dead"},
            "user_agent": "UA/1",
            "impersonate": "firefox144",
            "expires_at": None,  # never expires on a timer
        }

    async def test_dead_session_is_dropped_by_direct_fetch(self):
        monitor = self._monitor()
        self._seed_dead_session(monitor)

        class _Challenged:
            status_code = 403
            text = "<html><title>Just a moment...</title>"

            def raise_for_status(self):
                return None

        class _Session:
            async def __aenter__(self):
                return self

            async def __aexit__(self, *exc):
                return False

            async def get(self, *args, **kwargs):
                return _Challenged()

        orig = app.CurlAsyncSession
        app.CurlAsyncSession = lambda **kwargs: _Session()
        try:
            # The clearance is rejected -> fetch fails and the cache entry is dropped.
            self.assertIsNone(await app.fetch_with_cf_cookies(monitor, 20))
            self.assertIsNone(app.cf_cached_session(monitor))
            self.assertNotIn(app.cf_cache_key(monitor), app.cf_cookie_cache)
        finally:
            app.CurlAsyncSession = orig

    async def test_rewarm_after_death_passes_force(self):
        # After the dead session is dropped, the next refresh must force a fresh
        # challenge and store a session with no expiry.
        monitor = self._monitor()
        _FakeAsyncClient.payloads = {
            "https://linux.do/": {
                "cookies": {"_cfuvid": "new", "cf_clearance": "fresh"},
                "user_agent": "UA/2",
            }
        }
        self.assertTrue(await app.refresh_cf_cookie_cache(None, monitor, force=True))
        stored = app.cf_cookie_cache[app.cf_cache_key(monitor)]
        self.assertEqual(stored["cookies"]["cf_clearance"], "fresh")
        self.assertIsNone(stored["expires_at"], "refreshed session must not carry a TTL")
        get_params = [
            parse_qs(urlparse(url).query)
            for inst in _FakeAsyncClient.instances
            for method, url in inst.calls
            if method == "GET"
        ]
        self.assertTrue(get_params)
        self.assertEqual(get_params[0].get("force"), ["true"])


class CfDirectPauseTests(unittest.IsolatedAsyncioTestCase):
    """Cloudflare rejecting the curl_cffi fingerprint must pause the direct path."""

    def setUp(self):
        app.cf_direct_failures.clear()
        app.cf_direct_block_until.clear()
        app.cf_cookie_cache.clear()
        app.cf_cookie_refresh_locks.clear()
        self._env = dict(os.environ)

    def tearDown(self):
        app.cf_direct_failures.clear()
        app.cf_direct_block_until.clear()
        app.cf_cookie_cache.clear()
        app.cf_cookie_refresh_locks.clear()
        os.environ.clear()
        os.environ.update(self._env)

    def _monitor(self):
        return {
            "name": "Linux.do 福利",
            "url": "https://linux.do/c/welfare/36.json",
            "cf_bypass": True,
            "cf_bypass_url": "http://127.0.0.1:18001",
        }

    def test_defaults(self):
        monitor = self._monitor()
        self.assertEqual(app.cf_direct_failure_limit(), 2)
        self.assertEqual(app.cf_direct_block_seconds(), 1800)
        self.assertEqual(app.cf_direct_blocked_seconds(monitor), 0)

    def test_env_overrides(self):
        os.environ["CF_DIRECT_FAILURE_LIMIT"] = "5"
        os.environ["CF_DIRECT_BLOCK_SECONDS"] = "60"
        self.assertEqual(app.cf_direct_failure_limit(), 5)
        self.assertEqual(app.cf_direct_block_seconds(), 60)

    def test_first_rejection_does_not_pause(self):
        monitor = self._monitor()
        app.record_cf_direct_rejection(monitor)
        self.assertEqual(app.cf_direct_blocked_seconds(monitor), 0)

    def test_second_rejection_pauses_direct_fetch(self):
        monitor = self._monitor()
        app.record_cf_direct_rejection(monitor)
        app.record_cf_direct_rejection(monitor)
        self.assertGreater(app.cf_direct_blocked_seconds(monitor), 1700)

    def test_success_clears_counter_and_pause(self):
        monitor = self._monitor()
        app.record_cf_direct_rejection(monitor)
        app.record_cf_direct_rejection(monitor)
        self.assertGreater(app.cf_direct_blocked_seconds(monitor), 0)
        app.record_cf_direct_success(monitor)
        self.assertEqual(app.cf_direct_blocked_seconds(monitor), 0)
        self.assertNotIn(app.cf_cache_key(monitor), app.cf_direct_failures)

    def test_zero_block_seconds_disables_pause(self):
        os.environ["CF_DIRECT_BLOCK_SECONDS"] = "0"
        monitor = self._monitor()
        for _ in range(3):
            app.record_cf_direct_rejection(monitor)
        self.assertEqual(app.cf_direct_blocked_seconds(monitor), 0)

    def test_expired_pause_is_ignored(self):
        monitor = self._monitor()
        app.cf_direct_block_until[app.cf_cache_key(monitor)] = time.time() - 5
        self.assertEqual(app.cf_direct_blocked_seconds(monitor), 0)

    async def test_challenged_direct_fetches_engage_pause(self):
        monitor = self._monitor()

        class _Challenged:
            status_code = 403
            text = "<html><title>Just a moment...</title>"

            def raise_for_status(self):
                return None

        class _Session:
            async def __aenter__(self):
                return self

            async def __aexit__(self, *exc):
                return False

            async def get(self, *args, **kwargs):
                return _Challenged()

        def _seed():
            app.cf_cookie_cache[app.cf_cache_key(monitor)] = {
                "cookies": {"cf_clearance": "x"},
                "user_agent": "UA/1",
                "impersonate": "firefox144",
                "expires_at": None,
            }

        orig = app.CurlAsyncSession
        app.CurlAsyncSession = lambda **kwargs: _Session()
        try:
            for _ in range(2):
                # Each rejection drops the cached session, so re-seed it.
                _seed()
                self.assertIsNone(await app.fetch_with_cf_cookies(monitor, 5))
        finally:
            app.CurlAsyncSession = orig
        self.assertGreater(app.cf_direct_blocked_seconds(monitor), 0)


class CfFetchUrlMirrorModeTests(unittest.IsolatedAsyncioTestCase):
    """fetch_url must skip the direct path and its warmups while paused."""

    def setUp(self):
        app.cf_direct_failures.clear()
        app.cf_direct_block_until.clear()
        app.cf_cookie_cache.clear()
        app.cf_cookie_refresh_locks.clear()
        self.calls: list = []
        self._orig = {
            "fetch_with_cf_cookies": app.fetch_with_cf_cookies,
            "refresh_cf_cookie_cache": app.refresh_cf_cookie_cache,
            "fetch_via_cf_html": app.fetch_via_cf_html,
        }

    def tearDown(self):
        for name, fn in self._orig.items():
            setattr(app, name, fn)
        app.cf_direct_failures.clear()
        app.cf_direct_block_until.clear()
        app.cf_cookie_cache.clear()
        app.cf_cookie_refresh_locks.clear()

    def _monitor(self):
        return {
            "name": "Linux.do 福利",
            "url": "https://linux.do/c/welfare/36.json",
            "cf_bypass": True,
            "cf_bypass_url": "http://127.0.0.1:18001",
        }

    def _install(self, *, direct=None, mirror="mirror-body"):
        async def fake_direct(monitor, timeout):
            self.calls.append("direct")
            return direct

        async def fake_refresh(client, monitor, *, force=False):
            self.calls.append("refresh-force" if force else "refresh")
            return False

        async def fake_mirror(client, monitor):
            self.calls.append("mirror")
            return mirror

        app.fetch_with_cf_cookies = fake_direct
        app.refresh_cf_cookie_cache = fake_refresh
        app.fetch_via_cf_html = fake_mirror

    async def test_paused_monitor_goes_straight_to_mirror(self):
        monitor = self._monitor()
        app.cf_direct_block_until[app.cf_cache_key(monitor)] = time.time() + 600
        self._install()
        self.assertEqual(await app.fetch_url(None, monitor), "mirror-body")
        # No direct fetch and, crucially, no warmup at all.
        self.assertEqual(self.calls, ["mirror"])

    async def test_unpaused_monitor_still_tries_direct_first(self):
        monitor = self._monitor()
        self._install(direct="direct-body")
        self.assertEqual(await app.fetch_url(None, monitor), "direct-body")
        self.assertEqual(self.calls, ["direct"])

    async def test_paused_monitor_falls_back_to_direct_when_mirror_fails(self):
        monitor = self._monitor()
        app.cf_direct_block_until[app.cf_cache_key(monitor)] = time.time() + 600
        self._install(direct="direct-body", mirror=None)
        self.assertEqual(await app.fetch_url(None, monitor), "direct-body")
        self.assertEqual(self.calls, ["mirror", "direct"])


if __name__ == "__main__":
    unittest.main()