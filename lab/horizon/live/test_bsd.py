import copy
import tempfile
from pathlib import Path
import unittest

import bsd
import lab


def manifest():
    return {"target_v4": "192.168.254.131", "source_v4": "192.168.254.1",
            "target_v6": "fd66:66:12::2", "source_v6": "fd66:66:12::1",
            "guest_interface": "em0", "next_hop_mac": "00:0c:29:85:1a:62"}


def truth():
    return {"platform": "FreeBSD", "release": "15.1-RELEASE-p4", "fixture": "fixture-1",
            "interface": "em0", "local_v4": "192.168.254.131", "peer_v4": "192.168.254.1",
            "local_v6": "fd66:66:12::2", "peer_v6": "fd66:66:12::1", "port": 443,
            "sack": 1, "original_sack": 1, "listeners_closed": False,
            "addresses": {"exit_status": 0, "text": "ether 00:0c:29:85:1a:62\ninet 192.168.254.131 netmask\ninet6 fd66:66:12::2 prefixlen 64\n"},
            "routes": {"exit_status": 0, "text": "native routes"},
            "versions": {"exit_status": 0, "text": "15.1-RELEASE-p4"},
            "tcp_settings": {"exit_status": 0, "text": "net.inet.tcp.sack.enable: 1"},
            "firewall": {"exit_status": 1, "text": "pf module unavailable; no firewall change"}}


class BSDFixtureTests(unittest.TestCase):
    def test_registered_state_requires_native_identity_and_assigned_addresses(self):
        state, scope = truth(), manifest()
        self.assertEqual(bsd.validate_truth(state, scope, 1, "fixture-1"), "fixture-1")
        for key, value in (("sack", 0), ("fixture", "other"), ("listeners_closed", True),
                           ("local_v6", "fd66:66:12::3"), ("platform", "Linux")):
            changed = copy.deepcopy(state); changed[key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                bsd.validate_truth(changed, scope, 1, "fixture-1")
        changed = copy.deepcopy(state)
        changed["addresses"]["text"] = changed["addresses"]["text"].replace("00:0c:29:85:1a:62", "00:0c:29:85:1a:63")
        with self.assertRaisesRegex(ValueError, "MAC"): bsd.validate_truth(changed, scope, 1)
        changed = copy.deepcopy(state)
        changed["addresses"]["text"] = changed["addresses"]["text"].replace("fd66:66:12::2", "fd66:66:12::20")
        with self.assertRaisesRegex(ValueError, "not assigned"): bsd.validate_truth(changed, scope, 1)
        changed = copy.deepcopy(state)
        changed["tcp_settings"]["text"] = "net.inet.tcp.sack.enable: 0"
        with self.assertRaisesRegex(ValueError, "disagree"): bsd.validate_truth(changed, scope, 1)

    def test_scope_excludes_public_or_mixed_family_addresses(self):
        bsd.validate_scope(manifest())
        for key, value in (("target_v4", "8.8.8.8"), ("source_v6", "fe80::1"),
                           ("target_v6", "192.168.254.131"), ("source_v4", "192.168.254.131")):
            changed = manifest(); changed[key] = value
            with self.subTest(key=key), self.assertRaises(ValueError): bsd.validate_scope(changed)

    def test_missing_runs_retain_four_denominators_and_cannot_close_issue(self):
        with tempfile.TemporaryDirectory() as directory:
            out = Path(directory)
            lab.save(out / "protocol.json", bsd.PROTOCOL)
            recorded = manifest()
            recorded.update(protocol_sha256=lab.digest(out / "protocol.json"), planned=bsd.planned_runs(), results=[])
            lab.save(out / "manifest.json", recorded)
            summary = bsd.analyze(out, "/unused")
            self.assertEqual(len(recorded["planned"]), 12)
            self.assertEqual(len(summary["strata"]), 4)
            for row in summary["strata"].values():
                self.assertEqual(row["missing"], 3)
                self.assertEqual(row["accuracy_all_planned"], 0)
                self.assertFalse(row["null_gate_pass"])
            self.assertFalse(summary["issue_66_complete"])
            recorded["planned"] = recorded["planned"][:-1]
            lab.save(out / "manifest.json", recorded)
            with self.assertRaisesRegex(ValueError, "denominator"): bsd.analyze(out, "/unused")


if __name__ == "__main__": unittest.main()
