import base64
import collections
import json
import os
from pathlib import Path
import platform
import struct
import tempfile
import time
import unittest
from unittest.mock import patch

import lab


class BaselineTests(unittest.TestCase):
    @unittest.skipUnless(platform.system() == "Linux", "Linux child measurement")
    def test_cancellation_stops_measured_child_and_retains_resources(self):
        with tempfile.TemporaryDirectory() as directory:
            out = Path(directory)
            real_wait = os.wait4
            calls = 0
            def interrupted_wait(pid, flags):
                nonlocal calls
                calls += 1
                if calls == 1:
                    deadline = time.monotonic() + 2
                    while not (out / "child.pid").exists():
                        if time.monotonic() >= deadline:
                            self.fail("child did not start")
                        time.sleep(.01)
                    raise KeyboardInterrupt("operator cancellation")
                return real_wait(pid, flags)
            child = "import os,sys,time; open(sys.argv[1],'w').write(str(os.getpid())); time.sleep(30)"
            with patch.object(lab.os, "wait4", side_effect=interrupted_wait):
                with self.assertRaises(KeyboardInterrupt):
                    lab.measure(["python3", "-c", child, str(out / "child.pid")], out)
            pid = int((out / "child.pid").read_text())
            with self.assertRaises(ProcessLookupError):
                os.kill(pid, 0)
            self.assertNotEqual(json.loads((out / "resources.json").read_text())["exit_code"], 0)

    def test_scan_stream_includes_summary_and_rejects_extra_or_wrong_scope(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "stdout.txt"
            port = {"kind": "port", "target": "10.77.0.2", "port": 443, "transport": "tcp", "state": "open"}
            summary = {"kind": "scan", "status": "completed", "observations": 1}
            path.write_text(json.dumps(port) + "\n" + json.dumps(summary) + "\n")
            self.assertEqual(lab.scan_result(path, "10.77.0.2")["state"], "open")
            with self.assertRaisesRegex(ValueError, "scope"):
                lab.scan_result(path, "fd77:1::2")
            with path.open("a") as stream:
                stream.write(json.dumps(port) + "\n")
            with self.assertRaisesRegex(ValueError, "one observation"):
                lab.scan_result(path, "10.77.0.2")

    @unittest.skipUnless(platform.system() == "Linux", "wait4 RSS is recorded in Linux KiB")
    def test_measurement_retains_failed_command_output_and_per_child_resources(self):
        with tempfile.TemporaryDirectory() as directory:
            out = Path(directory)
            result = lab.measure(["python3", "-c", "import sys; print('retained'); sys.exit(7)"], out)
            self.assertEqual(result["exit_code"], 7)
            self.assertEqual((out / "stdout.txt").read_text(), "retained\n")
            self.assertGreater(result["peak_rss_kib"], 0)
            self.assertGreater(result["wall_seconds"], 0)
            self.assertEqual(json.loads((out / "resources.json").read_text()), result)

    def test_analyzer_cannot_promote_synthetic_evidence_to_live_ground_truth(self):
        with tempfile.TemporaryDirectory() as directory:
            out = Path(directory)
            lab.save(out / "protocol.json", lab.PROTOCOL)
            entry = {"id": "null-v4-clean-000", "platform": "Linux", "case": "null", "family": 4,
                     "impairment": "clean", "seed": 66000, "expected": "no-difference"}
            lab.save(out / "manifest.json", {"version": lab.PROTOCOL["version"], "completed": True,
                                            "protocol_sha256": lab.digest(out / "protocol.json"),
                                            "planned": [entry], "results": [{"id": entry["id"]}]})
            run = out / entry["id"]
            run.mkdir()
            for when in ("before", "after"):
                lab.save(run / f"truth-{when}.json", {"host": {"sack": 0}})
            with patch.object(lab, "command", return_value=json.dumps({"report": {"backend": "synthetic/stable"}})):
                with patch("builtins.print"):
                    result = lab.analyze(out, "/unused/nyxr")
            self.assertIn("synthetic evidence", result["rows"][0]["error"])
            self.assertFalse(result["issue_66_complete"])
            self.assertEqual(result["strata"]["Linux/null/v4/clean"]["invalid"], 1)

    def test_null_gate_requires_sixty_resolved_runs_and_zero_false_positives(self):
        null = {"outcome": "no-difference"}
        self.assertFalse(lab.stratum([null] * 59, 59, "no-difference")["null_gate_pass"])
        result = lab.stratum([null] * 60, 60, "no-difference")
        self.assertTrue(result["null_gate_pass"])
        self.assertAlmostEqual(result["zero_fp_upper_95"], 0.0487029133)
        bad = lab.stratum([null] * 59 + [{"outcome": "difference"}], 60, "no-difference")
        self.assertFalse(bad["null_gate_pass"])
        self.assertEqual(bad["false_positives"], 1)
        self.assertIsNone(bad["zero_fp_upper_95"])
        reverse = lab.stratum([null] * 59 + [{"outcome": "reverse-difference"}], 60, "no-difference")
        self.assertEqual(reverse["false_positives"], 1)
        self.assertFalse(reverse["null_gate_pass"])

    def test_wrong_direction_is_not_correct_effect_accuracy(self):
        report = {"comparison": {"status": "inferred", "pValue": .001,
                                 "controlOnlySack": 12, "treatmentOnlySack": 0}}
        result = lab.stratum([{"outcome": lab.outcome(report)}], 1, "difference")
        self.assertEqual(result["accuracy_all_planned"], 0)

    def test_attrition_never_improves_the_registered_denominator(self):
        null = {"outcome": "no-difference"}
        for extra in ({"outcome": "unresolved"}, {"error": "capture loss"}):
            result = lab.stratum([null] * 60 + [extra], 61, "no-difference")
            self.assertFalse(result["null_gate_pass"])
            self.assertEqual(result["accuracy_all_planned"], 60 / 61)
        result = lab.stratum([null] * 60, 61, "no-difference")
        self.assertFalse(result["null_gate_pass"])
        self.assertEqual(result["missing"], 1)

    def test_traffic_includes_runner_cleanup_and_timeout_is_not_a_reply(self):
        frame = base64.b64encode(b"frame").decode()
        report = {"completed": True, "packetsTx": 2, "captureBytes": 10, "backendDrops": 0,
                  "comparison": {"status": "unresolved", "pValue": 0.0001}, "trials": [
                      {"features": {"responseClass": "no-response"}, "qualityFlags": [],
                       "evidence": [{"direction": "tx", "frame": frame}]},
                      {"features": {"responseClass": "syn-ack", "rttNs": 1500000},
                       "qualityFlags": ["duplicate-reply"],
                       "evidence": [{"direction": "cleanup", "frame": frame}]}]}
        result = lab.metrics(report)
        self.assertEqual(result["runner_tx_bytes"], 10)
        self.assertEqual(result["timeouts"], 1)
        self.assertEqual(result["outcome"], "unresolved")
        self.assertEqual(result["rtt_ms_p95"], 1.5)

    def test_pcap_counts_all_wire_traffic_and_rejects_truncation(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "capture.pcap"
            header = struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
            record = struct.pack("<IIII", 1, 0, 3, 3) + b"abc"
            path.write_bytes(header + record + record)
            metrics, frames = lab.pcap(path)
            self.assertEqual(metrics["packets"], 2)
            self.assertEqual(metrics["bytes"], 6)
            self.assertEqual(frames, collections.Counter({b"abc": 2}))
            path.write_bytes(header + record[:-1])
            with self.assertRaisesRegex(ValueError, "truncated"):
                lab.pcap(path)
            path.write_bytes(header + struct.pack("<IIII", 1, 0, 3, 4) + b"abc")
            with self.assertRaisesRegex(ValueError, "truncated"):
                lab.pcap(path)

    def test_live_experiments_keep_matched_profiles_and_conservative_budgets(self):
        for target in ("10.77.0.2", "fd77:1::2"):
            e = lab.experiment(target, 66000)
            self.assertEqual(e["spec"]["execution"]["replicates"], 12)
            self.assertEqual(e["spec"]["limits"]["maxPackets"], 48)
            self.assertEqual(e["spec"]["control"]["steps"][1], e["spec"]["treatment"]["steps"][1])
            self.assertEqual(e["spec"]["scope"]["targets"], [target])


if __name__ == "__main__":
    unittest.main()
