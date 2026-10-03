"""Offline regression tests for clearance handling; no network, no credentials.

Covers two behaviours that previously hid a dead clearance or wasted a browser
challenge: health is reported only after Cloudflare accepts the session, and a
rejected session is replaced by a *forced* re-mint (the bypass hands back the
same dead session otherwise) which the claim then uses immediately.
"""
import ast
import logging
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

SOURCE = Path(__file__).with_name('cdk_claim.py')
CACHE_NAMES = {
    '_mint_clearance', 'cached_clearance',
    'refresh_clearance_if_stale', 'drop_clearance_cache',
    'clearance_probe_url', 'claim_probe_url', 'remember_cdk_link',
}


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
    }
    exec(compile(_subset({'verify_clearance'}), str(SOURCE), 'exec'), ns)
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
        '_probe_state': {'last_probe_at': 0.0, 'url': '', 'verified': False},
        '_probe_url_loaded': True,
        '_load_persisted_probe_url': lambda: '',
        '_persist_probe_url': lambda url: None,
        'cdk_clearance_probe_seconds': lambda: 600,
        'load_cdk_session': lambda **kw: SimpleNamespace(ok=False),
        'verify_clearance': Mock(return_value=True),
        'fetch_cdk_clearance': Mock(return_value=({'cf_clearance': 'fresh'}, 'UA')),
    }
    exec(compile(_subset(CACHE_NAMES), str(SOURCE), 'exec'), ns)
    return ns


def force_flags(ns):
    return [c.kwargs['force'] for c in ns['fetch_cdk_clearance'].call_args_list]


class ValidationTests(unittest.TestCase):
    """verify_clearance must only bless a response Cloudflare actually served."""

    def test_only_accepted_2xx_counts(self):
        cases = [
            (200, '', '', True), (204, '', '', True),
            (403, 'challenge', '', False), (200, 'challenge', '', False),
            (403, '', 'Just a moment', False), (401, '', '', False),
            (404, '', '', False), (429, '', '', False), (503, '', '', False),
        ]
        for status, header, body, expected in cases:
            with self.subTest(status=status, header=header):
                client = Mock()
                client.get.return_value = response(status, header, body)
                ns = verifier_namespace(client)
                self.assertEqual(expected, ns['verify_clearance']({'cf_clearance': 'fake'}, 'UA'))
                client.close.assert_called_once()

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
        ns['verify_clearance'] = Mock(return_value=False)
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
        ns['verify_clearance'].assert_not_called()

    def test_recent_verified_cache_is_reused_without_network(self):
        ns = namespace()
        ns['_clearance_cache'].update(cookies={'cf_clearance': 'cached'}, user_agent='UA')
        ns['_probe_state'].update(last_probe_at=time.time(), verified=True)
        self.assertTrue(ns['refresh_clearance_if_stale']()['ok'])
        ns['fetch_cdk_clearance'].assert_not_called()
        ns['verify_clearance'].assert_not_called()

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
        ns['verify_clearance'] = Mock(side_effect=[False, True])
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
        ns['verify_clearance'].assert_called_once()

    def test_validation_uses_the_caller_target(self):
        ns = namespace()
        ns['cached_clearance'](
            session_id='sid', probe_url='https://cdk.example/api/v1/projects/abc'
        )
        self.assertEqual(
            'https://cdk.example/api/v1/projects/abc',
            ns['verify_clearance'].call_args.args[3],
        )

    def test_probe_targets(self):
        ns = namespace()
        self.assertEqual('https://cdk.example/dashboard', ns['clearance_probe_url']())
        ns['remember_cdk_link']('https://cdk.example/receive/abc')
        self.assertEqual('https://cdk.example/receive/abc', ns['clearance_probe_url']())
        self.assertEqual(
            'https://cdk.example/api/v1/projects/abc', ns['claim_probe_url']('abc')
        )
        self.assertEqual('', ns['claim_probe_url'](''))


if __name__ == '__main__':
    unittest.main(verbosity=2)
