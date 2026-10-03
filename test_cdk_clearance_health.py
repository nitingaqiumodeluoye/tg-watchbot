"""Offline regression tests for clearance handling; no network, no credentials.

Covers two behaviours that previously hid a dead clearance or wasted a browser
challenge: health is reported only after Cloudflare accepts the session, and a
rejected session is replaced by a *forced* re-mint (the bypass hands back the
same dead session otherwise) which the claim then uses immediately.
"""
import ast
import logging
import os
import time
import unittest
from dataclasses import dataclass
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

SOURCE = Path(__file__).with_name('cdk_claim.py')
CACHE_NAMES = {
    '_mint_clearance', 'cached_clearance',
    'refresh_clearance_if_stale', 'drop_clearance_cache',
    'clearance_probe_url', 'claim_probe_url', 'remember_cdk_link',
    'remember_impersonate',
}
FINGERPRINT_NAMES = {
    'probe_clearance', '_impersonate_candidates',
    'remember_impersonate', 'active_impersonate', '_preset_sends_client_hints',
}
# Read the real constants instead of copying them: a duplicated list would keep
# passing after the source changed, which is exactly the bug these guard against.
CONSTANT_NAMES = {
    'DEFAULT_IMPERSONATE', '_IMPERSONATE_FALLBACKS', '_CLIENT_HINT_HEADERS',
    'CDK_MINT_SLOW_SECONDS',
}


def real_constants():
    tree = ast.parse(SOURCE.read_text(encoding='utf-8'))
    body = [
        n for n in tree.body
        if isinstance(n, (ast.Assign, ast.AnnAssign))
        and getattr(n.targets[0] if isinstance(n, ast.Assign) else n.target, 'id', '')
        in CONSTANT_NAMES
    ]
    ns = {}
    exec(compile(ast.Module(body=body, type_ignores=[]), str(SOURCE), 'exec'), ns)
    return {k: ns[k] for k in CONSTANT_NAMES}


def real_class(name):
    """Build the real class of that name from the source.

    The sliced modules do not carry ``from __future__ import annotations``, so
    annotations are evaluated at def time and every name they mention must exist
    in the namespace -- which is why this is needed at all.
    """
    tree = ast.parse(SOURCE.read_text(encoding='utf-8'))
    body = [n for n in tree.body if isinstance(n, ast.ClassDef) and n.name == name]
    assert body, f'class {name} not found in {SOURCE.name}'
    ns = {'dataclass': dataclass, **real_constants()}
    exec(compile(ast.Module(body=body, type_ignores=[]), str(SOURCE), 'exec'), ns)
    return ns[name]


MintBudget = real_class('MintBudget')
CDK_MINT_SLOW_SECONDS = real_constants()['CDK_MINT_SLOW_SECONDS']


NEW_CLIENT_NAMES = {'_new_client', '_preset_sends_client_hints'}


def namespace_for_hints():
    """Namespace holding the real _preset_sends_client_hints and the hint table."""
    ns = {'str': str, **real_constants()}
    exec(compile(_subset(NEW_CLIENT_NAMES), str(SOURCE), 'exec'), ns)
    return ns


def namespace_for_new_client(record):
    """Namespace with the real _new_client talking to a fake curl_cffi Session."""

    class FakeClient:
        def __init__(self, impersonate=None):
            record['impersonate'] = impersonate
            record['headers'] = {}
            self.headers = record['headers']
            self.cookies = SimpleNamespace(set=lambda *a, **k: None)

    ns = {
        'str': str, 'active_impersonate': lambda: 'safari184',
        'curl_requests': SimpleNamespace(Session=FakeClient),
        'RuntimeError': RuntimeError, **real_constants(),
    }
    exec(compile(_subset(NEW_CLIENT_NAMES), str(SOURCE), 'exec'), ns)
    return ns


def _subset(names):
    tree = ast.parse(SOURCE.read_text(encoding='utf-8'))
    body = [n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name in names]
    assert {n.name for n in body} == set(names), 'source functions renamed?'
    return ast.Module(body=body, type_ignores=[])


def verifier_namespace(client):
    """Namespace holding the *real* verify_clearance and a stubbed HTTP client."""
    ns = {
        'Any': object, 'logging': logging, 'logger': Mock(),
        'clearance_probe_url': lambda: 'https://cdk.example/health',
        '_new_client': Mock(return_value=client),
        '_browser_headers': lambda *a: {},
        '_challenge_like': lambda r: 'Just a moment' in r.text,
        'os': os,
        'active_impersonate': lambda: 'firefox133',
        'remember_impersonate': Mock(),
    }
    exec(compile(_subset({'verify_clearance'}), str(SOURCE), 'exec'), ns)
    return ns


def fingerprinter_namespace(passing, candidates=None):
    """Namespace holding the *real* probe_clearance with verify_clearance stubbed."""
    tried = []

    def fake_verify(cookies, user_agent, session_id='', url='', impersonate=''):
        tried.append(impersonate)
        return impersonate in passing

    ns = {
        'logger': Mock(), 'os': os,
        **real_constants(),
        'verify_clearance': fake_verify,
        '_persist_probe_state': lambda **kw: None,
        '_active_impersonate': '',
        '_preset_supported_cache': {},
        '_preset_supported': lambda name: name in (candidates or ()),
        'curl_requests': None,
    }
    exec(compile(_subset(FINGERPRINT_NAMES), str(SOURCE), 'exec'), ns)
    ns['tried'] = tried
    return ns


def response(status, header='', body=''):
    return SimpleNamespace(status_code=status, headers={'cf-mitigated': header}, text=body)


def namespace():
    """Namespace with every clearance function, HTTP and validation stubbed."""
    ns = {
        'Any': object, 'logging': logging, 'logger': Mock(), 'time': time,
        'CDK_BASE': 'https://cdk.example',
        'project_id_from_link': lambda link: str(link).rstrip('/').split('/')[-1],
        '_clearance_cache': {'cookies': {}, 'user_agent': ''},
        '_probe_state': {'last_probe_at': 0.0, 'url': '', 'verified': False, 'project_id': ''},
        '_probe_url_loaded': True,
        '_active_impersonate': '',
        '_preset_supported': lambda name: True,
        'MintBudget': MintBudget,
        'cdk_mint_budget': lambda: 2,
        '_load_persisted_probe_state': lambda: {},
        '_persist_probe_state': lambda **kw: None,
        'cdk_clearance_probe_seconds': lambda: 600,
        'load_cdk_session': lambda **kw: SimpleNamespace(ok=False),
        'verify_clearance': Mock(return_value=True),
        'probe_clearance': Mock(return_value=True),
        'fetch_cdk_clearance': Mock(return_value=({'cf_clearance': 'fresh'}, 'UA')),
    }
    exec(compile(_subset(CACHE_NAMES), str(SOURCE), 'exec'), ns)
    return ns


def force_flags(ns):
    return [c.kwargs['force'] for c in ns['fetch_cdk_clearance'].call_args_list]


class ValidationTests(unittest.TestCase):
    """verify_clearance must only bless a response Cloudflare actually served."""

    def test_only_origin_accepted_responses_count(self):
        cases = [
            (200, '', '', True), (204, '', '', True),
            (404, '', '', True),  # reached the origin: clearance was accepted
            (401, '', '', True),  # "未登录": CF cleared, app has no session cookie
            (403, 'challenge', '', False), (200, 'challenge', '', False),
            (403, '', 'Just a moment', False), (401, 'challenge', '', False),
            (403, '', '', False), (429, '', '', False), (503, '', '', False),
        ]
        for status, header, body, expected in cases:
            with self.subTest(status=status, header=header):
                client = Mock()
                client.get.return_value = response(status, header, body)
                ns = verifier_namespace(client)
                self.assertEqual(expected, ns['verify_clearance']({'cf_clearance': 'fake'}, 'UA'))
                client.close.assert_called_once()

    def test_preset_is_recorded_only_when_cloudflare_accepts_it(self):
        client = Mock()
        client.get.return_value = response(401)
        ns = verifier_namespace(client)
        ns['verify_clearance']({'cf_clearance': 'x'}, 'UA')
        self.assertEqual(['firefox133'], [c.args[0] for c in ns['remember_impersonate'].call_args_list])

        challenged = Mock()
        challenged.get.return_value = response(403, 'challenge')
        ns = verifier_namespace(challenged)
        ns['verify_clearance']({'cf_clearance': 'x'}, 'UA')
        ns['remember_impersonate'].assert_not_called()

    def test_missing_credentials_are_not_probed(self):
        client = Mock()
        ns = verifier_namespace(client)
        self.assertFalse(ns['verify_clearance']({}, 'UA'))
        self.assertFalse(ns['verify_clearance']({'cf_clearance': 'x'}, ''))
        ns['_new_client'].assert_not_called()

    def test_request_error_closes_client(self):
        client = Mock()
        client.get.side_effect = TimeoutError()
        ns = verifier_namespace(client)
        self.assertFalse(ns['verify_clearance']({'cf_clearance': 'x'}, 'UA'))
        client.close.assert_called_once()


class MintBudgetTests(unittest.TestCase):
    """One claim must not be able to solve challenges without end.

    Every browser session is a real challenge solve, and solving them is what
    provokes the rate limiting that killed the session -- so the budget is the
    brake that stops a failing claim from making its own situation worse.
    """

    def test_a_forced_mint_always_costs_one(self):
        ns = namespace()
        budget = MintBudget(limit=2)
        ns['cached_clearance'](session_id='sid', probe_url='https://cdk.example/x', force=True, budget=budget)
        self.assertEqual(1, budget.used)
        self.assertFalse(budget.exhausted)

    def test_a_fast_mint_is_a_cache_hit_and_costs_nothing(self):
        # The bypass answers from its own store in tens of milliseconds: no
        # challenge was solved, so it must not consume the allowance.
        ns = namespace()
        budget = MintBudget(limit=2)
        ns['cached_clearance'](session_id='sid', budget=budget)
        self.assertEqual(0, budget.used)

    def test_a_slow_unforced_mint_is_charged_as_a_browser(self):
        # Nothing cached on the bypass side => it launched a browser and solved a
        # challenge, even though the caller only asked for a cheap cache hit.
        ns = namespace()
        ns['fetch_cdk_clearance'] = Mock(side_effect=lambda **kw: (time.sleep(0.08), ({'cf_clearance': 'x'}, 'UA'))[1])
        budget = MintBudget(limit=2, slow_seconds=0.05)
        ns['cached_clearance'](session_id='sid', budget=budget)
        self.assertEqual(1, budget.used)

    def test_the_charge_threshold_sits_between_cache_hit_and_browser(self):
        # Measured: cache hits 24-200ms, browser launches 10.1-20.6s.
        self.assertGreater(CDK_MINT_SLOW_SECONDS, 0.2)
        self.assertLess(CDK_MINT_SLOW_SECONDS, 10.0)

    def test_no_mint_happens_once_the_budget_is_spent(self):
        ns = namespace()
        budget = MintBudget(limit=2, used=2)
        with self.assertRaises(RuntimeError):
            ns['cached_clearance'](session_id='sid', force=True, budget=budget)
        ns['fetch_cdk_clearance'].assert_not_called()
        self.assertEqual(2, budget.used)

    def test_the_cap_holds_across_repeated_refreshes(self):
        """The 2026-10-03 loop must stop: it launched four browsers in one claim."""
        ns = namespace()
        ns['probe_clearance'] = Mock(return_value=False)  # every session is rejected
        budget = MintBudget(limit=2)
        for _ in range(6):
            try:
                ns['cached_clearance'](session_id='sid', force=True, budget=budget)
            except RuntimeError:
                pass
        self.assertLessEqual(budget.used, 2)
        # 2 forced mints, then every later call refuses without touching the bypass.
        self.assertEqual(2, ns['fetch_cdk_clearance'].call_count)

    def test_without_a_budget_minting_is_unlimited(self):
        # The periodic probe deliberately has no budget: a single forced mint per
        # ten minutes is not a loop, and capping it would leave the cache cold.
        ns = namespace()
        ns['probe_clearance'] = Mock(return_value=False)
        for _ in range(4):
            ns['cached_clearance'](session_id='sid', force=True)
        self.assertEqual(4, ns['fetch_cdk_clearance'].call_count)

    def test_limit_is_configurable_and_bounded(self):
        for env, expected in (('', 2), ('1', 1), ('3', 3), ('99', 6), ('0', 1), ('junk', 2)):
            with self.subTest(env=env):
                ns = {'os': os, 'CDK_MINT_BUDGET_DEFAULT': 2}
                body = [
                    n for n in ast.parse(SOURCE.read_text(encoding='utf-8')).body
                    if isinstance(n, ast.FunctionDef) and n.name == 'cdk_mint_budget'
                ]
                exec(compile(ast.Module(body=body, type_ignores=[]), str(SOURCE), 'exec'), ns)
                if env:
                    os.environ['CDK_MINT_BUDGET'] = env
                else:
                    os.environ.pop('CDK_MINT_BUDGET', None)
                try:
                    self.assertEqual(expected, ns['cdk_mint_budget']())
                finally:
                    os.environ.pop('CDK_MINT_BUDGET', None)


class FingerprintTests(unittest.TestCase):
    """The TLS preset decides the outcome, so it must be discovered, not assumed."""

    def test_probe_walks_presets_until_one_is_accepted(self):
        ns = fingerprinter_namespace(
            passing={'firefox144'},
            candidates={'firefox133', 'firefox135', 'firefox144'},
        )
        self.assertTrue(ns['probe_clearance']({'cf_clearance': 'x'}, 'UA'))
        self.assertEqual(['firefox133', 'firefox135', 'firefox144'], ns['tried'])

    def test_probe_stops_at_the_first_accepted_preset(self):
        ns = fingerprinter_namespace(
            passing={'firefox135'}, candidates={'firefox133', 'firefox135'}
        )
        self.assertTrue(ns['probe_clearance']({'cf_clearance': 'x'}, 'UA'))
        self.assertEqual(['firefox133', 'firefox135'], ns['tried'])

    def test_probe_reports_failure_only_after_every_preset(self):
        ns = fingerprinter_namespace(passing=set(), candidates={'firefox133', 'firefox135'})
        self.assertFalse(ns['probe_clearance']({'cf_clearance': 'x'}, 'UA'))
        self.assertEqual(['firefox133', 'firefox135'], ns['tried'])

    def test_unsupported_presets_are_dropped(self):
        ns = fingerprinter_namespace(passing=set(), candidates={'firefox133'})
        self.assertEqual(('firefox133',), ns['_impersonate_candidates']())

    def test_the_safari_preset_is_tried_first(self):
        ns = fingerprinter_namespace(
            passing=set(), candidates={'firefox133', 'firefox135', 'firefox144', 'safari184'}
        )
        # Firefox presets send no Client Hints and get challenged, so they must not
        # be the first thing every cold start pays a rejected request for.
        self.assertEqual('safari184', ns['_impersonate_candidates']()[0])
        self.assertEqual('safari184', real_constants()['DEFAULT_IMPERSONATE'])

    def test_the_candidate_list_spans_several_browser_families(self):
        fallbacks = real_constants()['_IMPERSONATE_FALLBACKS']
        families = {n.split('1')[0].rstrip('_') for n in fallbacks}
        for family in ('safari', 'chrome', 'firefox'):
            self.assertIn(family, families)
        self.assertGreaterEqual(len(fallbacks), 10)

    def test_client_hints_are_defined_for_the_critical_ch_demand(self):
        hints = real_constants()['_CLIENT_HINT_HEADERS']
        for key in ('sec-ch-ua', 'sec-ch-ua-mobile', 'sec-ch-ua-platform',
                    'sec-ch-ua-arch', 'sec-ch-ua-bitness', 'sec-ch-ua-full-version'):
            self.assertIn(key, hints)

    def test_only_firefox_presets_need_manual_client_hints(self):
        ns = namespace_for_hints()
        self.assertFalse(ns['_preset_sends_client_hints']('firefox133'))
        self.assertFalse(ns['_preset_sends_client_hints']('firefox'))
        self.assertTrue(ns['_preset_sends_client_hints']('safari184'))
        self.assertTrue(ns['_preset_sends_client_hints']('chrome124'))

    def test_new_client_attaches_hints_for_firefox_only(self):
        for preset, expect in (('firefox133', True), ('safari184', False)):
            with self.subTest(preset=preset):
                made = {}
                ns = namespace_for_new_client(made)
                ns['_new_client']('UA', {'cf_clearance': 'x'}, impersonate=preset)
                self.assertEqual(expect, 'sec-ch-ua' in made['headers'])
                self.assertEqual(preset, made['impersonate'])

    def test_env_override_wins(self):
        ns = fingerprinter_namespace(
            passing=set(), candidates={'firefox135', 'firefox133'}
        )
        os.environ['CDK_IMPERSONATE'] = 'firefox135'
        try:
            self.assertEqual('firefox135', ns['_impersonate_candidates']()[0])
        finally:
            del os.environ['CDK_IMPERSONATE']

    def test_a_typo_in_the_env_cannot_break_every_request(self):
        ns = fingerprinter_namespace(passing=set(), candidates={'firefox133'})
        os.environ['CDK_IMPERSONATE'] = 'not-a-browser'
        try:
            self.assertEqual(('firefox133',), ns['_impersonate_candidates']())
        finally:
            del os.environ['CDK_IMPERSONATE']


class RefreshTests(unittest.TestCase):

    def test_cold_start_tries_bypass_cache_before_force(self):
        ns = namespace()
        result = ns['refresh_clearance_if_stale']()
        self.assertTrue(result['ok'])
        self.assertGreater(result['verified_at'], 0)
        self.assertEqual([False], force_flags(ns))
        self.assertEqual(1, ns['fetch_cdk_clearance'].call_count)

    def test_unvalidated_mint_is_never_reported_healthy(self):
        ns = namespace()
        ns['probe_clearance'] = Mock(return_value=False)
        result = ns['refresh_clearance_if_stale']()
        self.assertFalse(result['ok'])
        self.assertEqual(0.0, ns['_probe_state']['last_probe_at'])
        self.assertFalse(ns['_probe_state']['verified'])
        # A session that never validated is retried with a forced refresh before
        # being accepted, and stays available so the claim can report the real
        # error instead of refusing to run at all.
        self.assertEqual([False, True], force_flags(ns))
        self.assertEqual({'cf_clearance': 'fresh'}, ns['_clearance_cache']['cookies'])

    def test_no_session_at_all_raises(self):
        ns = namespace()
        ns['fetch_cdk_clearance'] = Mock(return_value=({}, ''))
        ns['verify_clearance'] = Mock()
        result = ns['refresh_clearance_if_stale']()
        self.assertFalse(result['ok'])
        self.assertIn('no usable session', result['error'])
        self.assertEqual({}, ns['_clearance_cache']['cookies'])
        ns['probe_clearance'].assert_not_called()

    def test_recent_verified_cache_is_reused_without_network(self):
        ns = namespace()
        ns['_clearance_cache'].update(cookies={'cf_clearance': 'cached'}, user_agent='UA')
        ns['_probe_state'].update(last_probe_at=time.time(), verified=True)
        self.assertTrue(ns['refresh_clearance_if_stale']()['ok'])
        ns['fetch_cdk_clearance'].assert_not_called()
        ns['probe_clearance'].assert_not_called()

    def test_stale_but_accepted_cache_is_reused(self):
        ns = namespace()
        ns['_clearance_cache'].update(cookies={'cf_clearance': 'cached'}, user_agent='UA')
        ns['_probe_state']['last_probe_at'] = time.time() - 1000
        cookies, ua = ns['cached_clearance'](session_id='sid')
        self.assertEqual('cached', cookies['cf_clearance'])
        ns['fetch_cdk_clearance'].assert_not_called()

    def test_rejected_cache_is_replaced_by_a_forced_mint(self):
        ns = namespace()
        ns['_clearance_cache'].update(cookies={'cf_clearance': 'dead'}, user_agent='UA')
        ns['_probe_state']['last_probe_at'] = time.time() - 1000
        # The cached session is rejected; the freshly minted one is accepted.
        ns['probe_clearance'] = Mock(side_effect=[False, True])
        cookies, ua = ns['cached_clearance'](session_id='sid')
        # The bypass still holds 'dead' in its own cache, so the refresh must be
        # forced or the retry replays the same rejected session.
        self.assertEqual([True], force_flags(ns))
        self.assertEqual('fresh', cookies['cf_clearance'])
        self.assertTrue(ns['_probe_state']['verified'])

    def test_force_skips_the_cached_session(self):
        ns = namespace()
        ns['_clearance_cache'].update(cookies={'cf_clearance': 'cached'}, user_agent='UA')
        ns['_probe_state'].update(last_probe_at=time.time(), verified=True)
        cookies, ua = ns['cached_clearance'](session_id='sid', force=True)
        self.assertEqual([True], force_flags(ns))
        self.assertEqual('fresh', cookies['cf_clearance'])
        ns['probe_clearance'].assert_called_once()

    def test_validation_uses_the_caller_target(self):
        ns = namespace()
        ns['cached_clearance'](
            session_id='sid', probe_url='https://cdk.example/api/v1/projects/abc'
        )
        self.assertEqual(
            'https://cdk.example/api/v1/projects/abc',
            ns['probe_clearance'].call_args.args[3],
        )

    def test_probe_target_prefers_the_project_api(self):
        ns = namespace()
        # Nothing remembered yet: the warmup page is the only safe target.
        self.assertEqual('https://cdk.example/dashboard', ns['clearance_probe_url']())
        self.assertEqual(
            'https://cdk.example/api/v1/projects/abc', ns['claim_probe_url']('abc')
        )
        self.assertEqual('', ns['claim_probe_url'](''))
        ns['remember_cdk_link']('https://cdk.example/receive/abc-def')
        # The periodic probe must target the same request a claim makes.
        self.assertEqual(
            'https://cdk.example/api/v1/projects/abc-def', ns['clearance_probe_url']()
        )
        self.assertEqual('https://cdk.example/receive/abc-def', ns['_probe_state']['url'])

    def test_persisted_state_is_reloaded_after_restart(self):
        ns = namespace()
        ns['_probe_url_loaded'] = False
        ns['_load_persisted_probe_state'] = lambda: {
            'probe_project_id': 'from-disk', 'probe_url': 'https://cdk.example/receive/from-disk'
        }
        self.assertEqual(
            'https://cdk.example/api/v1/projects/from-disk', ns['clearance_probe_url']()
        )

    def test_legacy_state_without_project_id_is_migrated(self):
        ns = namespace()
        ns['_probe_url_loaded'] = False
        # Pre-API state only stored the page URL.
        ns['_load_persisted_probe_state'] = lambda: {
            'probe_url': 'https://cdk.example/receive/legacy-id'
        }
        self.assertEqual(
            'https://cdk.example/api/v1/projects/legacy-id', ns['clearance_probe_url']()
        )

    def test_mint_targets_the_same_url_it_validates(self):
        """Cloudflare challenges per path, so the browser must load the claim URL."""
        ns = namespace()
        ns['cached_clearance'](
            session_id='sid', probe_url='https://cdk.example/api/v1/projects/abc', force=True
        )
        self.assertEqual(
            'https://cdk.example/api/v1/projects/abc',
            ns['fetch_cdk_clearance'].call_args.kwargs['target_url'],
        )

    def test_mint_target_follows_the_periodic_probe(self):
        ns = namespace()
        ns['remember_cdk_link']('https://cdk.example/receive/api-id')
        ns['refresh_clearance_if_stale']()
        self.assertEqual(
            'https://cdk.example/api/v1/projects/api-id',
            ns['fetch_cdk_clearance'].call_args.kwargs['target_url'],
        )

    def test_mint_target_is_the_warmup_page_when_nothing_is_known(self):
        # With no give-away seen yet, both the probe and the browser fall back to
        # /dashboard; the important part is that they agree.
        ns = namespace()
        ns['refresh_clearance_if_stale']()
        self.assertEqual(
            'https://cdk.example/dashboard',
            ns['fetch_cdk_clearance'].call_args.kwargs['target_url'],
        )
        self.assertEqual(
            ns['clearance_probe_url'](), ns['fetch_cdk_clearance'].call_args.kwargs['target_url']
        )

    def test_persisted_preset_is_restored_after_a_restart(self):
        ns = namespace()
        ns['_probe_url_loaded'] = False
        ns['_load_persisted_probe_state'] = lambda: {
            'probe_project_id': 'from-disk', 'impersonate': 'safari180'
        }
        ns['_preset_supported'] = lambda name: name == 'safari180'
        ns['clearance_probe_url']()
        self.assertEqual('safari180', ns['_active_impersonate'])

    def test_an_unsupported_persisted_preset_is_ignored(self):
        ns = namespace()
        ns['_probe_url_loaded'] = False
        ns['_load_persisted_probe_state'] = lambda: {'impersonate': 'not-a-browser'}
        ns['_preset_supported'] = lambda name: False
        ns['clearance_probe_url']()
        self.assertEqual('', ns['_active_impersonate'])

    def test_mid_flight_challenge_does_not_discard_a_validated_clearance(self):
        """claim_link's PermissionError handler must not drop the session.

        Cloudflare's decision flaps (200 then 403 on the same URL 155ms apart), so
        a challenged request is not evidence the clearance is dead; dropping it buys
        another browser challenge for a session that may still be accepted.
        """
        tree = ast.parse(SOURCE.read_text(encoding='utf-8'))
        func = next(
            n for n in tree.body
            if isinstance(n, ast.FunctionDef) and n.name == 'claim_link'
        )
        outer = next(
            n for n in func.body
            if isinstance(n, ast.Try)
            and any(getattr(h.type, 'id', '') == 'PermissionError' for h in n.handlers)
        )
        handler = next(
            h for h in outer.handlers
            if getattr(h.type, 'id', '') == 'PermissionError'
        )
        code = ast.unparse(handler)
        self.assertIn('_probe_state.update', code)
        self.assertNotIn('drop_clearance_cache', code)

    def test_remembered_link_is_persisted(self):
        ns = namespace()
        saved = {}
        ns['_persist_probe_state'] = lambda **kw: saved.update(kw)
        ns['remember_cdk_link']('https://cdk.example/receive/keep-me')
        self.assertEqual(
            {'probe_project_id': 'keep-me', 'probe_url': 'https://cdk.example/receive/keep-me'},
            saved,
        )


if __name__ == '__main__':
    unittest.main(verbosity=2)
