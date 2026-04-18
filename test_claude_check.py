#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""claude_check.py 单元测试"""

import io
import json
import socket
import unittest
from unittest import mock

import claude_check


class TestColors(unittest.TestCase):
    def setUp(self):
        # 保存原始值
        self._orig = {attr: getattr(claude_check.Colors, attr)
                      for attr in ('GREEN', 'RED', 'YELLOW', 'BLUE', 'BOLD', 'RESET')}

    def tearDown(self):
        for attr, val in self._orig.items():
            setattr(claude_check.Colors, attr, val)

    def test_disable_clears_all(self):
        claude_check.Colors.disable()
        for attr in ('GREEN', 'RED', 'YELLOW', 'BLUE', 'BOLD', 'RESET'):
            self.assertEqual(getattr(claude_check.Colors, attr), '')


class TestCheckIPv6(unittest.TestCase):
    @mock.patch('claude_check.socket.has_ipv6', False)
    def test_no_ipv6_support(self):
        connected, addr = claude_check._check_ipv6()
        self.assertFalse(connected)
        self.assertIsNone(addr)

    @mock.patch('claude_check.socket.has_ipv6', True)
    @mock.patch('claude_check.socket.socket')
    def test_ipv6_connected(self, mock_sock_cls):
        mock_sock = mock.MagicMock()
        mock_sock.getsockname.return_value = ('2001:db8::1', 0, 0, 0)
        mock_sock_cls.return_value = mock_sock
        connected, addr = claude_check._check_ipv6()
        self.assertTrue(connected)
        self.assertEqual(addr, '2001:db8::1')
        mock_sock.close.assert_called_once()

    @mock.patch('claude_check.socket.has_ipv6', True)
    @mock.patch('claude_check.socket.socket')
    def test_ipv6_unreachable(self, mock_sock_cls):
        mock_sock = mock.MagicMock()
        mock_sock.connect.side_effect = OSError('unreachable')
        mock_sock_cls.return_value = mock_sock
        connected, addr = claude_check._check_ipv6()
        self.assertFalse(connected)
        self.assertIsNone(addr)
        mock_sock.close.assert_called_once()


class TestCalculateRisk(unittest.TestCase):
    def _base_results(self):
        return {
            'ipv6': {'connected': False},
            'dns_leak': {'status': 'safe'},
            'ip_quality': {
                'status': 'ok',
                'hosting': False,
                'proxy': False,
                'timezone_match': True,
            },
            'cloudflare_waf': {'status': 'pass'},
            'api_connectivity': {'status': 'reachable'},
        }

    def test_all_safe_is_low(self):
        level, suggestions = claude_check.calculate_risk(self._base_results())
        self.assertEqual(level, 'LOW')
        self.assertEqual(suggestions, [])

    def test_ipv6_leak_is_high(self):
        r = self._base_results()
        r['ipv6']['connected'] = True
        level, _ = claude_check.calculate_risk(r)
        self.assertEqual(level, 'HIGH')

    def test_hosting_ip_is_medium(self):
        r = self._base_results()
        r['ip_quality']['hosting'] = True
        level, _ = claude_check.calculate_risk(r)
        self.assertEqual(level, 'MEDIUM')

    def test_multiple_reds_is_critical(self):
        r = self._base_results()
        r['ipv6']['connected'] = True
        r['dns_leak']['status'] = 'leaked'
        level, suggestions = claude_check.calculate_risk(r)
        self.assertEqual(level, 'CRITICAL')
        self.assertTrue(len(suggestions) >= 2)

    def test_timezone_mismatch(self):
        r = self._base_results()
        r['ip_quality']['timezone_match'] = False
        level, _ = claude_check.calculate_risk(r)
        self.assertEqual(level, 'HIGH')

    def test_waf_blocked(self):
        r = self._base_results()
        r['cloudflare_waf']['status'] = 'blocked'
        level, _ = claude_check.calculate_risk(r)
        self.assertEqual(level, 'HIGH')

    def test_api_banned(self):
        r = self._base_results()
        r['api_connectivity']['status'] = 'hard_banned'
        level, _ = claude_check.calculate_risk(r)
        self.assertEqual(level, 'HIGH')


class TestFmtOffset(unittest.TestCase):
    def test_positive(self):
        self.assertEqual(claude_check._fmt_offset(28800), 'UTC+8.0')

    def test_negative(self):
        self.assertEqual(claude_check._fmt_offset(-18000), 'UTC-5.0')

    def test_zero(self):
        self.assertEqual(claude_check._fmt_offset(0), 'UTC+0.0')


class TestParseArgs(unittest.TestCase):
    @mock.patch('sys.argv', ['claude_check.py'])
    def test_defaults(self):
        args = claude_check.parse_args()
        self.assertFalse(args.skip_api)
        self.assertFalse(args.skip_web)
        self.assertFalse(args.json_output)
        self.assertFalse(args.no_color)

    @mock.patch('sys.argv', ['claude_check.py', '--json', '--skip-api', '--skip-web', '--no-color'])
    def test_all_flags(self):
        args = claude_check.parse_args()
        self.assertTrue(args.skip_api)
        self.assertTrue(args.skip_web)
        self.assertTrue(args.json_output)
        self.assertTrue(args.no_color)


if __name__ == '__main__':
    unittest.main()
