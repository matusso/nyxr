import base64
import copy
import json
from pathlib import Path
import sys
import tempfile
import unittest

import bsd_study as study
import lab
from test_bsd import manifest, truth


class BSDStudyTests(unittest.TestCase):
    def test_fixed_plan_keeps_all_separate_denominators(self):
        rows = study.planned_runs()
        self.assertEqual(len(rows), 588)
        self.assertEqual(len({r["seed"] for r in rows}), 588)
        for role in ("development", "reserved"):
            for family in (4, 6):
                for condition in ("clean", "loss-jitter"):
                    for sack, count in ((0, 60), (1, 12)):
                        self.assertEqual(sum((r["role"], r["family"], r["impairment"], r["sack"]) ==
                            (role, family, condition, sack) for r in rows), count)
        with tempfile.TemporaryDirectory() as directory:
            out = Path(directory)
            lab.save(out / "protocol.json", study.PROTOCOL)
            data = {"protocol_sha256": lab.digest(out / "protocol.json"), "planned": rows,
                "results": [], "fixtures": {"development": manifest(), "reserved": manifest()}}
            lab.save(out / "manifest.json", data)
            summary = study.analyze(out, "/unused")
            self.assertEqual(sum(s["missing"] for s in summary["strata"].values()), 588)
            self.assertFalse(summary["issue_66_complete"])
            self.assertFalse(summary["independence_established"])
            data["planned"] = rows[:-1]; lab.save(out / "manifest.json", data)
            with self.assertRaisesRegex(ValueError, "denominator"): study.analyze(out, "/unused")

    def test_native_vnet_truth_rejects_unscoped_and_disabled_rules(self):
        state = truth()
        state.update(jailed=1, condition="clean")
        state["firewall"] = {"exit_status": 0, "text": "net.inet.ip.fw.enable: 1\nnet.inet6.ip6.fw.enable: 1\n65535 allow ip from any to any\n"}
        entry = {"sack": 1, "impairment": "clean"}
        study.validate_truth(state, manifest(), entry)
        bad = copy.deepcopy(state); bad["jailed"] = 0
        with self.assertRaisesRegex(ValueError, "jailed"): study.validate_truth(bad, manifest(), entry)
        bad = copy.deepcopy(state); bad["firewall"]["text"] += "60066 1 60 deny ip from any to any\n"
        with self.assertRaisesRegex(ValueError, "unexpected"): study.validate_truth(bad, manifest(), entry)
        bad = copy.deepcopy(state); bad["firewall"]["text"] = bad["firewall"]["text"].replace("enable: 1", "enable: 0")
        with self.assertRaisesRegex(ValueError, "disabled"): study.validate_truth(bad, manifest(), entry)

    def test_canonical_options_handle_padding_and_reject_malformed_sack(self):
        def encoded(value): return base64.b64encode(bytes(value)).decode()
        self.assertTrue(study.sack_option(encoded([2, 4, 5, 180, 1, 4, 2, 0])))
        self.assertFalse(study.sack_option(encoded([2, 4, 5, 180, 0, 4, 2, 0])))
        with self.assertRaises(ValueError): study.sack_option(encoded([4, 3, 0]))
        with self.assertRaises(ValueError): study.sack_option(encoded([2, 4, 5]))

    def test_native_dummynet_settings_must_match_registered_impairment(self):
        state = truth()
        state.update(jailed=1, condition="loss-jitter")
        state["firewall"] = {"exit_status": 0, "text":
            'net.inet.ip.fw.enable: 1\nnet.inet6.ip6.fw.enable: 1\n'
            '60066 0 0 pipe 6066 tcp from 192.168.254.131 443 to 192.168.254.1 out tcpflags syn,ack\n'
            '60067 0 0 pipe 6066 tcp from fd66:66:12::2 443 to fd66:66:12::1 out tcpflags syn,ack\n'
            '65535 allow ip from any to any\n'
            '06066: 100.000 Mbit/s 0 ms\nq 50 sl. plr 0.050000\n'
            ' profile: name "nyxr66-uniform-15-25" loss 1.000000 samples 128\n'}
        entry = {"sack": 1, "impairment": "loss-jitter"}
        study.validate_truth(state, manifest(), entry)
        for before, after in (("0.050000", "0.100000"), ("100.000", "10.000"), ("samples 128", "samples 64"),
                              ("to 192.168.254.1", "to any")):
            bad = copy.deepcopy(state)
            bad["firewall"]["text"] = bad["firewall"]["text"].replace(before, after)
            with self.subTest(before=before), self.assertRaises(ValueError):
                study.validate_truth(bad, manifest(), entry)

    def test_stationarity_flags_never_establish_iid(self):
        result = study.diagnostics([{"rtt_ms_p50": n} for n in range(1, 61)])
        self.assertTrue(result["drift_flag"])
        self.assertTrue(result["lag_flag"])
        self.assertFalse(result["iid_established"])
        result = study.diagnostics([{"rtt_ms_p50": 2}] * 60)
        self.assertFalse(result["drift_flag"])
        self.assertIsNone(result["lag_one_rtt_correlation"])
        self.assertFalse(result["stationarity_established"])

    def test_worker_child_deadline_retains_resources_and_reaps_child(self):
        with tempfile.TemporaryDirectory() as directory:
            out = Path(directory)
            result = study.measure([sys.executable, "-c", "import time; time.sleep(5)"], out, .03)
            self.assertTrue(result["external_deadline_reached"])
            self.assertNotEqual(result["exit_code"], 0)
            self.assertLess(result["wall_seconds"], 4)
            self.assertEqual(json.loads((out / "resources.json").read_text()), result)


if __name__ == "__main__": unittest.main()
