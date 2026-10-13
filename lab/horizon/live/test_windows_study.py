import unittest

import windows_study


class WindowsStudyAdmissionTests(unittest.TestCase):
    def test_separate_family_denominators_and_seeds(self):
        ipv4, ipv6 = windows_study.plan(4), windows_study.plan(6)
        for family, entries, first in ((4, ipv4, 68000), (6, ipv6, 68100)):
            self.assertEqual(len(entries), 15)
            self.assertEqual([e["mode"] for e in entries], ["clean"] * 12 + ["blocked"] * 3)
            self.assertEqual([e["seed"] for e in entries], list(range(first, first + 15)))
            self.assertTrue(all(e["family"] == family for e in entries))
        self.assertFalse({e["id"] for e in ipv4} & {e["id"] for e in ipv6})

    def test_firewall_control_rejects_widened_peer_or_missing_block(self):
        state = {
            "block_rule_present": True,
            "block_rule": [{"Enabled": 1, "Direction": 1, "Action": 4}],
            "block_addresses": [{"LocalAddress": "192.168.254.130", "RemoteAddress": "192.168.254.1"}],
            "block_ports": [{"Protocol": "TCP", "LocalPort": "443"}],
        }
        windows_study.validate_rule(state, "block", "192.168.254.130", "192.168.254.1", 443, 4)
        state["block_addresses"][0]["RemoteAddress"] = "Any"
        with self.assertRaisesRegex(ValueError, "address scope"):
            windows_study.validate_rule(state, "block", "192.168.254.130", "192.168.254.1", 443, 4)
        state["block_rule_present"] = False
        with self.assertRaisesRegex(ValueError, "presence"):
            windows_study.validate_rule(state, "block", "192.168.254.130", "192.168.254.1", 443, 4)


if __name__ == "__main__":
    unittest.main()
