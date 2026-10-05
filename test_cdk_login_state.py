"""Tests for CDK login-session lifetime, detection and fail-fast behaviour.

Context (measured 2026-10-05): the `linux_do_cdk_session_id` token expires exactly
7 days after it is issued, and nothing noticed. `verify_clearance` counts a 401 as
*proof Cloudflare was cleared*, which is true and says nothing about the login, so
the probe logged "cdk clearance probe ok" every 10 minutes for the 9 hours the
session was dead -- while every give-away failed with `未登录`. On top of that,
`confirm_received` retried on *any* exception, so a dead login bought a fresh
browser challenge (12.7s and 14.8s on two real give-aways) that could not help.

Run:  python -m unittest test_cdk_login_state -v
"""
from __future__ import annotations

import base64
import json
import os
import sqlite3
import tempfile
import time
import unittest
from unittest import mock

import cdk_claim


def make_token(issued_at: float | None = None, opaque: str = "ABCDEF") -> str:
    """Build a token shaped like the real one: base64(`<epoch>|<opaque>|...`)."""
    epoch = int(issued_at if issued_at is not None else time.time())
    payload = f"{epoch}|{opaque}|signature".encode()
    return base64.urlsafe_b64encode(payload).decode().rstrip("=")


class SessionLifetimeTests(unittest.TestCase):
    """The embedded issue time is what makes the 7-day TTL visible at all."""

    def test_issue_time_is_read_from_the_token(self):
        issued = 1790577669.0  # the real token's value
        token = make_token(issued)
        self.assertAlmostEqual(cdk_claim.session_issued_at(token), issued, places=0)

    def test_issue_time_of_a_garbage_token_is_zero(self):
        for bad in ("", "not-a-token", "!!!!", "MTIzNA"):
            with self.subTest(token=bad):
                self.assertEqual(cdk_claim.session_issued_at(bad), 0.0)

    def test_non_epoch_first_field_is_rejected(self):
        # A base64 blob that decodes to text but carries no timestamp must not be
        # mistaken for one, or every arbitrary value would look like a session.
        token = base64.urlsafe_b64encode(b"hello|world").decode().rstrip("=")
        self.assertEqual(cdk_claim.session_issued_at(token), 0.0)

    def test_remaining_seconds_counts_down_from_issue_time(self):
        token = make_token(time.time() - 86400)
        remaining = cdk_claim.session_remaining_seconds(token)
        self.assertIsNotNone(remaining)
        self.assertAlmostEqual(remaining / 86400, 6.0, delta=0.01)

    def test_remaining_seconds_is_negative_once_expired(self):
        token = make_token(time.time() - 8 * 86400)
        remaining = cdk_claim.session_remaining_seconds(token)
        self.assertIsNotNone(remaining)
        self.assertLess(remaining, 0)

    def test_expiry_is_seven_days_after_issue(self):
        # Pins the measurement: issued 2026-09-28T06:41:09Z, first 401 at
        # 2026-10-05T06:42:45Z (+96s, and the probe only samples every 10 min).
        issued = 1790577669.0
        token = make_token(issued)
        self.assertEqual(cdk_claim.cdk_session_ttl_days(), 7.0)
        self.assertAlmostEqual(
            cdk_claim.session_remaining_seconds(token) + time.time(),
            issued + 7 * 86400,
            delta=1,
        )

    def test_ttl_is_configurable(self):
        with mock.patch.dict(os.environ, {"CDK_SESSION_TTL_DAYS": "3"}):
            self.assertEqual(cdk_claim.cdk_session_ttl_days(), 3.0)

    def test_remaining_seconds_of_unknown_token_is_none(self):
        self.assertIsNone(cdk_claim.session_remaining_seconds("garbage"))


class LoginDeadDetectionTests(unittest.TestCase):
    """`未登录` must be distinguishable from a Cloudflare challenge."""

    def test_real_origin_message_is_detected(self):
        self.assertTrue(cdk_claim.login_dead_error("未登录"))

    def test_common_variants_are_detected(self):
        for message in ("请先登录", "登录已过期", "登录失效", "请登录后重试"):
            with self.subTest(message=message):
                self.assertTrue(cdk_claim.login_dead_error(message))

    def test_business_errors_are_not_login_errors(self):
        for message in ("无库存", "项目已结束", "需要支付 LDC 后领取", "积分不足", ""):
            with self.subTest(message=message):
                self.assertFalse(cdk_claim.login_dead_error(message))

    def test_none_is_not_a_login_error(self):
        self.assertFalse(cdk_claim.login_dead_error(None))

    def test_app_error_raises_login_expired(self):
        with self.assertRaises(cdk_claim.LoginExpired):
            cdk_claim.raise_for_app_error({"error_msg": "未登录"})

    def test_app_error_raises_plain_runtime_error_otherwise(self):
        with self.assertRaises(RuntimeError) as ctx:
            cdk_claim.raise_for_app_error({"error_msg": "无库存"})
        self.assertNotIsInstance(ctx.exception, cdk_claim.LoginExpired)

    def test_no_error_msg_raises_nothing(self):
        cdk_claim.raise_for_app_error({"data": {}})
        cdk_claim.raise_for_app_error({})

    def test_login_expired_is_not_a_permission_error(self):
        # The whole point: callers key the "spend a browser" decision on
        # PermissionError, so LoginExpired must not be one.
        self.assertFalse(issubclass(cdk_claim.LoginExpired, PermissionError))
        self.assertTrue(issubclass(cdk_claim.LoginExpired, RuntimeError))

    def test_project_info_raises_login_expired(self):
        class _Resp:
            status_code = 401
            text = '{"data":null,"error_msg":"未登录"}'

            def json(self):
                return {"data": None, "error_msg": "未登录"}

        class _Client:
            headers = {"User-Agent": "UA"}

            def get(self, *a, **k):
                return _Resp()

        with self.assertRaises(cdk_claim.LoginExpired):
            cdk_claim.get_project_info("pid", _Client())

    def test_user_info_raises_login_expired(self):
        class _Resp:
            status_code = 401
            text = '{"data":null,"error_msg":"未登录"}'

            def json(self):
                return {"data": None, "error_msg": "未登录"}

        class _Client:
            headers = {"User-Agent": "UA"}

            def get(self, *a, **k):
                return _Resp()

        with self.assertRaises(cdk_claim.LoginExpired):
            cdk_claim.get_user_info(_Client())


class SessionValueNormalisationTests(unittest.TestCase):
    """A pasted value must be recognisable, or the panel silently stores junk."""

    def test_bare_token_is_kept(self):
        token = make_token()
        self.assertEqual(cdk_claim.normalize_session_value(token), token)

    def test_name_value_pair_is_unwrapped(self):
        token = make_token()
        self.assertEqual(
            cdk_claim.normalize_session_value(f"linux_do_cdk_session_id={token}"),
            token,
        )

    def test_whole_cookie_header_is_unwrapped(self):
        token = make_token()
        raw = f"Cookie: _t=abc; linux_do_cdk_session_id={token}; other=1"
        self.assertEqual(cdk_claim.normalize_session_value(raw), token)

    def test_quotes_are_stripped(self):
        token = make_token()
        self.assertEqual(cdk_claim.normalize_session_value(f'"{token}"'), token)

    def test_empty_input_is_empty_output(self):
        self.assertEqual(cdk_claim.normalize_session_value(""), "")
        self.assertEqual(cdk_claim.normalize_session_value("   "), "")

    def test_linuxdo_t_cookie_is_rejected_with_a_useful_message(self):
        # The credential people actually reach for, and the one that cannot log
        # into cdk.linux.do. Storing it silently would be worse than failing.
        bogus = base64.urlsafe_b64encode(b"some-random-session-blob").decode().rstrip("=")
        with self.assertRaises(ValueError) as ctx:
            cdk_claim.normalize_session_value(bogus)
        self.assertIn("linux_do_cdk_session_id", str(ctx.exception))

    def test_arbitrary_text_is_rejected(self):
        with self.assertRaises(ValueError):
            cdk_claim.normalize_session_value("hello world")

    def test_cookie_header_without_our_field_is_rejected(self):
        with self.assertRaises(ValueError):
            cdk_claim.normalize_session_value("Cookie: _t=abc; other=1")


class PanelSessionStoreTests(unittest.TestCase):
    """The panel writes sqlite; the loader must prefer it over the legacy file."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.db_path = os.path.join(self.tmp.name, "state.sqlite3")
        self.env = mock.patch.dict(
            os.environ,
            {
                "CDK_STATE_DB": self.db_path,
                "CDK_SESSION_FILE": os.path.join(self.tmp.name, "cdk_session.json"),
            },
            clear=False,
        )
        self.env.start()
        self.addCleanup(self.env.stop)
        os.environ.pop("CDK_SESSION_ID", None)
        cdk_claim.forget_session_cache()
        self.addCleanup(cdk_claim.forget_session_cache)

    def _write_panel_value(self, value: str) -> None:
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                "CREATE TABLE IF NOT EXISTS app_meta ("
                "meta_key TEXT PRIMARY KEY, meta_value TEXT, updated_at TEXT)"
            )
            conn.execute(
                "INSERT INTO app_meta(meta_key, meta_value, updated_at) VALUES(?,?,?) "
                "ON CONFLICT(meta_key) DO UPDATE SET meta_value=excluded.meta_value",
                (cdk_claim.PANEL_SESSION_META_KEY, value, cdk_claim.now_iso()),
            )
            conn.commit()

    def test_missing_db_reports_no_panel_value(self):
        self.assertEqual(cdk_claim.panel_session_id(), "")

    def test_panel_value_is_read(self):
        token = make_token()
        self._write_panel_value(token)
        self.assertEqual(cdk_claim.panel_session_id(), token)

    def test_save_panel_session_round_trips(self):
        token = make_token()
        self.assertEqual(cdk_claim.save_panel_session(token), token)
        cdk_claim.forget_session_cache()
        self.assertEqual(cdk_claim.load_cdk_session(refresh=True).session_id, token)

    def test_save_panel_session_accepts_a_cookie_header(self):
        token = make_token()
        cdk_claim.save_panel_session(f"linux_do_cdk_session_id={token}")
        self.assertEqual(cdk_claim.panel_session_id(), token)

    def test_save_panel_session_rejects_a_bad_value(self):
        with self.assertRaises(ValueError):
            cdk_claim.save_panel_session("not-a-token")
        self.assertEqual(cdk_claim.panel_session_id(), "")

    def test_panel_value_beats_the_legacy_file(self):
        file_token, panel_token = make_token(opaque="FILE"), make_token(opaque="PANEL")
        with open(os.environ["CDK_SESSION_FILE"], "w", encoding="utf-8") as fh:
            json.dump({"linux_do_cdk_session_id": file_token, "user_agent": "UA"}, fh)
        self._write_panel_value(panel_token)
        cdk_claim.forget_session_cache()
        self.assertEqual(cdk_claim.load_cdk_session(refresh=True).session_id, panel_token)

    def test_env_var_beats_everything(self):
        env_token = make_token(opaque="ENV")
        self._write_panel_value(make_token(opaque="PANEL"))
        os.environ["CDK_SESSION_ID"] = env_token
        cdk_claim.forget_session_cache()
        self.assertEqual(cdk_claim.load_cdk_session(refresh=True).session_id, env_token)

    def test_legacy_file_still_works_when_the_panel_is_empty(self):
        file_token = make_token(opaque="FILE")
        with open(os.environ["CDK_SESSION_FILE"], "w", encoding="utf-8") as fh:
            json.dump({"linux_do_cdk_session_id": file_token, "user_agent": "UA"}, fh)
        cdk_claim.forget_session_cache()
        self.assertEqual(cdk_claim.load_cdk_session(refresh=True).session_id, file_token)

    def test_cli_sync_and_panel_agree(self):
        # Both writers must land on the same value, or a CLI sync would appear to
        # do nothing whenever a panel value exists.
        cli_token = make_token(opaque="CLI")
        cdk_claim.save_cdk_session(cli_token, source="cli")
        cdk_claim.forget_session_cache()
        self.assertEqual(cdk_claim.panel_session_id(), cli_token)
        self.assertEqual(cdk_claim.load_cdk_session(refresh=True).session_id, cli_token)

    def test_saving_invalid_and_valid_uses_the_same_cache_reset(self):
        first = make_token(opaque="FIRST")
        second = make_token(opaque="SECOND")
        cdk_claim.save_cdk_session(first, source="cli")
        self.assertEqual(cdk_claim.load_cdk_session(refresh=True).session_id, first)
        cdk_claim.save_cdk_session(second, source="cli")
        # No explicit refresh=True: the save must have dropped the cache.
        self.assertEqual(cdk_claim.load_cdk_session().session_id, second)


class CheckLoginStateTests(unittest.TestCase):
    """`check_login_state` is the check that the clearance probe cannot do."""

    def setUp(self):
        cdk_claim.forget_session_cache()
        self.addCleanup(cdk_claim.forget_session_cache)
        self.token = make_token()
        self._patches = [
            mock.patch.object(cdk_claim, "load_cdk_session",
                              lambda refresh=False: cdk_claim.CdkSession(session_id=self.token, user_agent="UA")),
            mock.patch.object(cdk_claim, "cached_clearance",
                              lambda **kw: ({"cf_clearance": "x"}, "UA")),
            mock.patch.object(cdk_claim, "_new_client", lambda *a, **k: _FakeClient(self.payload)),
        ]
        self.payload: dict = {}
        for p in self._patches:
            p.start()
            self.addCleanup(p.stop)

    def test_account_present_is_ok(self):
        self.payload = {"data": {"username": "me", "score": 120}}
        state = cdk_claim.check_login_state()
        self.assertTrue(state["ok"])
        self.assertEqual(state["account"]["username"], "me")

    def test_not_logged_in_is_not_ok(self):
        self.payload = {"data": None, "error_msg": "未登录"}
        state = cdk_claim.check_login_state()
        self.assertFalse(state["ok"])
        self.assertEqual(state["detail"], "未登录")

    def test_empty_account_is_not_ok(self):
        self.payload = {"data": {}, "error_msg": ""}
        state = cdk_claim.check_login_state()
        self.assertFalse(state["ok"])

    def test_missing_session_is_reported_without_a_request(self):
        with mock.patch.object(cdk_claim, "load_cdk_session",
                               lambda refresh=False: cdk_claim.CdkSession()):
            state = cdk_claim.check_login_state()
        self.assertFalse(state["ok"])
        self.assertIn("no session", state["detail"])

    def test_remaining_seconds_travel_with_the_verdict(self):
        token = make_token(time.time() - 86400)
        with mock.patch.object(cdk_claim, "load_cdk_session",
                               lambda refresh=False: cdk_claim.CdkSession(session_id=token, user_agent="UA")):
            self.payload = {"data": {"username": "me"}}
            state = cdk_claim.check_login_state()
        self.assertAlmostEqual((state["remaining_seconds"] or 0) / 86400, 6.0, delta=0.01)

    def test_missing_clearance_is_not_ok(self):
        with mock.patch.object(cdk_claim, "cached_clearance", lambda **kw: ({}, "UA")):
            state = cdk_claim.check_login_state()
        self.assertFalse(state["ok"])


class _Resp:
    def __init__(self, payload: dict, status: int = 200):
        self._payload = payload
        self.status_code = status
        self.text = json.dumps(payload)

    def json(self):
        return self._payload


class _FakeClient:
    """Minimal curl_cffi-shaped client returning one canned payload."""

    def __init__(self, payload: dict):
        self._payload = payload
        self.headers = {"User-Agent": "UA"}

    def get(self, *a, **k):
        return _Resp(self._payload)

    def post(self, *a, **k):
        return _Resp(self._payload)

    def close(self):
        pass


class ClaimFailFastTests(unittest.TestCase):
    """A dead login must abort a claim without spending browser time."""

    def setUp(self):
        cdk_claim.forget_session_cache()
        self.addCleanup(cdk_claim.forget_session_cache)
        self.token = make_token()
        self.cleared = []

    def _install(self, *, project_error: Exception | None, payload: dict | None = None):
        def fake_cached_clearance(**kwargs):
            if kwargs.get("force"):
                self.cleared.append("forced")
            return {"cf_clearance": "x"}, "UA"

        def fake_get_project_info(project_id, client):
            if project_error:
                raise project_error
            return {"name": "P", "is_received": False}

        patches = [
            mock.patch.object(cdk_claim, "load_cdk_session",
                              lambda refresh=False: cdk_claim.CdkSession(session_id=self.token, user_agent="UA")),
            mock.patch.object(cdk_claim, "cached_clearance", fake_cached_clearance),
            mock.patch.object(cdk_claim, "_new_client", lambda *a, **k: _FakeClient(payload or {})),
            mock.patch.object(cdk_claim, "get_project_info", fake_get_project_info),
            mock.patch.object(cdk_claim, "get_user_info", lambda client: {"score": 200}),
        ]
        for p in patches:
            p.start()
            self.addCleanup(p.stop)

    def test_dead_login_gives_not_logged_in(self):
        self._install(project_error=cdk_claim.LoginExpired("未登录"))
        result = cdk_claim.claim_link("https://cdk.linux.do/receive/1cea31d3-583e-46a8-91d3-9ac83b850aac")
        self.assertFalse(result.ok)
        self.assertEqual(result.reason, "not_logged_in")
        self.assertIn("7 天", result.error)

    def test_dead_login_never_spends_a_browser_challenge(self):
        self._install(project_error=cdk_claim.LoginExpired("未登录"))
        cdk_claim.claim_link("https://cdk.linux.do/receive/1cea31d3-583e-46a8-91d3-9ac83b850aac")
        self.assertEqual(self.cleared, [], "a dead login must not trigger a forced mint")

    def test_cloudflare_is_still_reported_as_cloudflare(self):
        self._install(project_error=PermissionError("cloudflare"))
        result = cdk_claim.claim_link("https://cdk.linux.do/receive/1cea31d3-583e-46a8-91d3-9ac83b850aac")
        self.assertEqual(result.reason, "cloudflare")
        self.assertNotIn("not_logged_in", result.reason)

    def test_dead_login_at_post_receive_is_not_retried(self):
        # The project query succeeded, then the POST said 未登录: one captcha was
        # already spent, and no further attempt can help.
        self._install(project_error=None, payload={"data": None, "error_msg": "未登录"})
        solved = []
        with mock.patch.object(cdk_claim, "solve_captcha",
                               lambda url: (solved.append(url) or "token", "UA")):
            result = cdk_claim.claim_link("https://cdk.linux.do/receive/1cea31d3-583e-46a8-91d3-9ac83b850aac")
        self.assertEqual(result.reason, "not_logged_in")
        self.assertEqual(len(solved), 1, "no retry loop for a dead login")


class ConfirmReceivedTests(unittest.TestCase):
    """The read-back must not buy a challenge for a failure CF cannot fix."""

    def setUp(self):
        cdk_claim.forget_session_cache()
        self.addCleanup(cdk_claim.forget_session_cache)
        self.token = make_token()
        self.forced = []

    def _install(self, error: Exception | None):
        def fake_cached_clearance(**kwargs):
            if kwargs.get("force"):
                self.forced.append("forced")
            return {"cf_clearance": "x"}, "UA"

        def fake_get_project_info(project_id, client):
            raise error

        for target, value in (
            ("cached_clearance", fake_cached_clearance),
            ("_new_client", lambda *a, **k: _FakeClient({})),
            ("get_project_info", fake_get_project_info),
        ):
            p = mock.patch.object(cdk_claim, target, value)
            p.start()
            self.addCleanup(p.stop)

    @staticmethod
    def _result() -> "cdk_claim.ClaimResult":
        return cdk_claim.ClaimResult(project_id="1cea31d3-583e-46a8-91d3-9ac83b850aac",
                                     reason="error", error="boom")

    def test_dead_login_does_not_force_a_new_clearance(self):
        self._install(cdk_claim.LoginExpired("未登录"))
        cdk_claim.confirm_received(self._result(), cdk_claim.CdkSession(session_id=self.token))
        self.assertEqual(self.forced, [])

    def test_cloudflare_does_force_a_new_clearance(self):
        self._install(PermissionError("cloudflare"))
        cdk_claim.confirm_received(self._result(), cdk_claim.CdkSession(session_id=self.token))
        self.assertEqual(self.forced, ["forced"])

    def test_a_generic_failure_does_not_force_a_new_clearance(self):
        # This is the 12.7s bug: any exception used to buy a browser challenge.
        self._install(OSError("connection reset"))
        cdk_claim.confirm_received(self._result(), cdk_claim.CdkSession(session_id=self.token))
        self.assertEqual(self.forced, [])

    def test_a_successful_read_back_still_confirms(self):
        p = mock.patch.object(
            cdk_claim, "get_project_info",
            lambda project_id, client: {"is_received": True, "received_content": "GT-XXXX"},
        )
        p.start()
        self.addCleanup(p.stop)
        with mock.patch.object(cdk_claim, "cached_clearance",
                               lambda **kw: ({"cf_clearance": "x"}, "UA")):
            with mock.patch.object(cdk_claim, "_new_client", lambda *a, **k: _FakeClient({})):
                result = self._result()
                cdk_claim.confirm_received(result, cdk_claim.CdkSession(session_id=self.token))
        self.assertTrue(result.ok)
        self.assertEqual(result.content, "GT-XXXX")
        self.assertEqual(result.reason, "confirmed_after_failure")


class LoginStateIndependenceTests(unittest.TestCase):
    """Documents *why* the clearance verdict cannot stand in for the login one."""

    def test_a_401_still_counts_as_clearance_verified(self):
        # `verify_clearance` is right about Cloudflare and silent about the login;
        # that asymmetry is the whole reason `check_login_state` exists.
        class _Resp:
            status_code = 401
            text = '{"data":null,"error_msg":"未登录"}'
            headers: dict = {}

            def json(self):
                return {"data": None, "error_msg": "未登录"}

        class _Client:
            def get(self, *a, **k):
                return _Resp()

            def close(self):
                pass

        with mock.patch.object(cdk_claim, "_new_client", lambda *a, **k: _Client()):
            self.assertTrue(
                cdk_claim.verify_clearance({"cf_clearance": "x"}, "UA", "sess", "https://cdk.linux.do/x")
            )


if __name__ == "__main__":
    unittest.main()
