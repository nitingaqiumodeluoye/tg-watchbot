"""Offline regression tests for clearance health reporting; no network or credentials."""
import ast
import logging
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

SOURCE = Path(__file__).with_name('cdk_claim.py')
NAMES = {'verify_clearance', 'cached_clearance', 'refresh_clearance_if_stale', 'drop_clearance_cache'}


def namespace():
    tree = ast.parse(SOURCE.read_text(encoding='utf-8'))
    subset = ast.Module(body=[n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name in NAMES], type_ignores=[])
    ns = {
        'Any': object, 'logging': logging, 'logger': Mock(), 'time': time,
        '_clearance_cache': {'cookies': {}, 'user_agent': ''},
        '_probe_state': {'last_probe_at': 0.0, 'url': ''},
        'clearance_probe_url': lambda: 'https://example.invalid/health',
        'cdk_clearance_probe_seconds': lambda: 600,
        '_browser_headers': lambda *args: {},
        '_challenge_like': lambda r: 'Just a moment' in r.text,
        'load_cdk_session': lambda: SimpleNamespace(ok=False),
    }
    exec(compile(subset, str(SOURCE), 'exec'), ns)
    return ns


class HealthTests(unittest.TestCase):
    def test_response_matrix(self):
        cases = [(200, '', '', True), (204, '', '', True),
                 (403, 'challenge', '', False), (200, 'challenge', '', False),
                 (403, '', 'Just a moment', False), (401, '', '', False),
                 (404, '', '', False), (429, '', '', False), (503, '', '', False)]
        for status, header, body, expected in cases:
            with self.subTest(status=status, header=header):
                ns = namespace()
                client = Mock()
                client.get.return_value = SimpleNamespace(status_code=status, headers={'cf-mitigated': header}, text=body)
                ns['_new_client'] = Mock(return_value=client)
                self.assertEqual(ns['verify_clearance']({'cf_clearance': 'fake'}, 'fake-UA'), expected)
                client.close.assert_called_once()

    def test_missing_credentials(self):
        ns = namespace()
        ns['_new_client'] = Mock()
        self.assertFalse(ns['verify_clearance']({}, 'UA'))
        self.assertFalse(ns['verify_clearance']({'cf_clearance': 'fake'}, ''))
        ns['_new_client'].assert_not_called()

    def test_timeout_closes_client(self):
        ns = namespace()
        client = Mock()
        client.get.side_effect = TimeoutError()
        ns['_new_client'] = Mock(return_value=client)
        self.assertFalse(ns['verify_clearance']({'cf_clearance': 'fake'}, 'UA'))
        client.close.assert_called_once()

    def test_unverified_cookie_does_not_report_ok(self):
        ns = namespace()
        ns['fetch_cdk_clearance'] = Mock(return_value=({'cf_clearance': 'fake'}, 'UA'))
        ns['verify_clearance'] = Mock(return_value=False)
        result = ns['refresh_clearance_if_stale']()
        self.assertFalse(result['ok'])
        self.assertIn('no verified session', result['error'])
        self.assertEqual(ns['_clearance_cache']['cookies'], {})
        self.assertEqual(ns['_probe_state']['last_probe_at'], 0)
        self.assertEqual(ns['fetch_cdk_clearance'].call_count, 2)

    def test_missing_cookie_does_not_report_ok(self):
        ns = namespace()
        ns['fetch_cdk_clearance'] = Mock(return_value=({}, 'UA'))
        ns['verify_clearance'] = Mock()
        self.assertFalse(ns['refresh_clearance_if_stale']()['ok'])
        ns['verify_clearance'].assert_not_called()

    def test_verified_cookie_reports_ok(self):
        ns = namespace()
        ns['fetch_cdk_clearance'] = Mock(return_value=({'cf_clearance': 'fake'}, 'UA'))
        ns['verify_clearance'] = Mock(return_value=True)
        result = ns['refresh_clearance_if_stale']()
        self.assertTrue(result['ok'])
        self.assertGreater(result['verified_at'], 0)
        self.assertEqual(ns['fetch_cdk_clearance'].call_count, 1)

    def test_recent_verified_cache_is_reused(self):
        ns = namespace()
        ns['_clearance_cache'].update(cookies={'cf_clearance': 'fake'}, user_agent='UA')
        ns['_probe_state']['last_probe_at'] = time.time()
        ns['fetch_cdk_clearance'] = Mock()
        ns['verify_clearance'] = Mock()
        self.assertTrue(ns['refresh_clearance_if_stale']()['ok'])
        ns['fetch_cdk_clearance'].assert_not_called()
        ns['verify_clearance'].assert_not_called()

    def test_stale_failed_cache_is_cleared(self):
        ns = namespace()
        ns['_clearance_cache'].update(cookies={'cf_clearance': 'old'}, user_agent='UA')
        ns['fetch_cdk_clearance'] = Mock(return_value=({'cf_clearance': 'new'}, 'UA'))
        ns['verify_clearance'] = Mock(return_value=False)
        self.assertFalse(ns['refresh_clearance_if_stale']()['ok'])
        self.assertEqual(ns['_clearance_cache']['cookies'], {})


if __name__ == '__main__':
    unittest.main(verbosity=2)
