import json
import collections
import socket
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import lab
import windows


class WindowsFixtureTests(unittest.TestCase):
    def test_zero_drop_empty_or_wrong_scope_scanner_capture_is_invalid(self):
        frame = bytearray(54)
        frame[12:14], frame[14], frame[23] = b'\x08\x00', 0x45, 6
        frame[26:30], frame[30:34] = socket.inet_aton('192.168.254.1'), socket.inet_aton('192.168.254.130')
        frame[36:38], frame[47] = b'\x01\xbb', 2
        frames = collections.Counter({bytes(frame): 1})
        windows.validate_scan_capture(frames, '192.168.254.1', '192.168.254.130', 1)
        for bad, target, count in (({}, '192.168.254.130', 1),
                                  (frames, '192.168.254.131', 1),
                                  (frames, '192.168.254.130', 2)):
            with self.assertRaisesRegex(ValueError, 'missing from independent'):
                windows.validate_scan_capture(bad, '192.168.254.1', target, count)

    def test_private_allowlist_rejects_external_and_ipv6_targets(self):
        self.assertEqual(windows.private_v4('192.168.254.130'), '192.168.254.130')
        for address in ('8.8.8.8', '127.0.0.1', '192.0.2.1', 'fd77::2'):
            with self.assertRaises(ValueError): windows.private_v4(address)

    def test_native_truth_rejects_wider_firewall_or_different_listener(self):
        state = {'platform': 'Windows', 'build': '26100', 'fixture': 'fixture-1',
                 'local_address': '192.168.254.130', 'peer_address': '192.168.254.1', 'port': 443,
                 'adapter': {'MacAddress': '00-0C-29-7D-91-CB'}, 'fixture_rule_present': True,
                 'fixture_rule': [{'Enabled': 1, 'Direction': 1, 'Action': 2}],
                 'fixture_addresses': [{'LocalAddress': ['192.168.254.130'], 'RemoteAddress': ['192.168.254.1']}],
                 'fixture_ports': [{'Protocol': 'TCP', 'LocalPort': ['443']}],
                 'tcp_global': 'native', 'tcp_settings': ['native'], 'firewall_profiles': ['enabled']}
        def check(value, fixture='fixture-1'):
            return windows.validate_truth(value, '192.168.254.130', '192.168.254.1', '00:0c:29:7d:91:cb', fixture)
        self.assertEqual(check(state), 'fixture-1')
        scalar = json.loads(json.dumps(state))
        scalar['fixture_addresses'][0] = {'LocalAddress': '192.168.254.130', 'RemoteAddress': '192.168.254.1'}
        scalar['fixture_ports'][0]['LocalPort'] = '443'
        self.assertEqual(check(scalar), 'fixture-1')
        with self.assertRaisesRegex(ValueError, 'identity'): check(state, 'other')
        modified = json.loads(json.dumps(state))
        modified['fixture_addresses'][0]['RemoteAddress'] = ['Any']
        with self.assertRaisesRegex(ValueError, 'address scope'): check(modified)
        modified['fixture_addresses'][0]['RemoteAddress'] = ['192.168.254.1', 'Any']
        with self.assertRaisesRegex(ValueError, 'address scope'): check(modified)
        modified = json.loads(json.dumps(state))
        modified['adapter']['MacAddress'] = '00-00-00-00-00-00'
        with self.assertRaisesRegex(ValueError, 'MAC'): check(modified)

    def test_missing_windows_runs_remain_in_denominator_and_cannot_close_issue(self):
        with tempfile.TemporaryDirectory() as directory:
            out = Path(directory)
            lab.save(out / 'protocol.json', windows.PROTOCOL)
            planned = [{'id': f'windows-v4-clean-{n:03d}', 'seed': 66100+n,
                        'platform': 'Windows', 'family': 4, 'impairment': 'clean', 'expected': 'difference'}
                       for n in range(3)]
            manifest = {'protocol_sha256': lab.digest(out / 'protocol.json'),
                        'planned': planned, 'results': [], 'target': '192.168.254.130',
                        'source': '192.168.254.1', 'next_hop_mac': '00:0c:29:7d:91:cb'}
            lab.save(out / 'manifest.json', manifest)
            summary = windows.analyze(out, '/unused')
            self.assertEqual(summary['stratum']['missing'], 3)
            self.assertEqual(summary['stratum']['accuracy_all_planned'], 0)
            self.assertFalse(summary['issue_66_complete'])
            manifest['planned'] = planned[:2]
            lab.save(out / 'manifest.json', manifest)
            with self.assertRaisesRegex(ValueError, 'denominator'): windows.analyze(out, '/unused')

    def test_darwin_rss_bytes_are_normalized_to_kib(self):
        class Usage:
            ru_utime = .1
            ru_stime = .2
            ru_maxrss = 8192
        with tempfile.TemporaryDirectory() as directory:
            with patch.object(lab.platform, 'system', return_value='Darwin'), \
                 patch.object(lab.os, 'posix_spawnp', return_value=123), \
                 patch.object(lab.os, 'wait4', return_value=(123, 0, Usage())):
                result = lab.measure(['/unused'], Path(directory))
            self.assertEqual(result['peak_rss_kib'], 8)


if __name__ == '__main__': unittest.main()
