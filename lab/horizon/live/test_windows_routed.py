import json
from pathlib import Path
import unittest

import windows_routed

HERE = Path(__file__).resolve().parent
COUNT4 = "count tcp from 10.66.22.2 443 to 10.66.21.1 out xmit em0 tcpflags syn,ack"
COUNT6 = "count tcp from fd66:66:22::2 443 to fd66:66:21::1 out xmit em0 tcpflags syn,ack"


def router_text(condition="clean", extra="", modules="ipfw.ko"):
    rules = [f"60064   3   180 {COUNT4}", f"60065   3   240 {COUNT6}"]
    if condition == "drop":
        rules += [f"60066   2   120 {COUNT4.replace('count', 'deny')}",
                  f"60067   2   160 {COUNT6.replace('count', 'deny')}"]
    rules += ["65535   0     0 count ip from any to any not // orphaned dynamic states counter",
              "65535 196 22397 allow ip from any to any"]
    return (f"fixture=f1\ncondition={condition}\nutc=2026-10-19T09:00:00Z\ninterface=em0\n--- system\n15.1-RELEASE-p4\n"
            "kern.boottime: { sec = 1, usec = 0 } Mon Oct 19 08:23:00 2026\nnet.inet.ip.forwarding: 1\n"
            "net.inet6.ip6.forwarding: 1\nnet.inet.ip.redirect: 0\nnet.inet6.ip6.redirect: 0\n"
            "net.inet.ip.fw.enable: 1\nnet.inet6.ip6.fw.enable: 1\n--- interface\nem0: flags\n--- ipfw\n"
            + "\n".join(rules) + extra + "\n--- modules\n 1   19 0xffff000000000000  14236e8 kernel\n"
            + f" 5    1 0xffff0000ae300000    4b000 {modules}\n--- end\n")


class WindowsRoutedTests(unittest.TestCase):
    def test_denominators_seeds_and_order_are_frozen(self):
        seeds = set()
        sizes = {"native": 15, "feasibility": 3, "null": 60, "restore": 1}
        for phase, size in sizes.items():
            for family in (4, 6):
                rows = windows_routed.plan(phase, family)
                self.assertEqual(len(rows), size)
                self.assertEqual(rows, windows_routed.plan(phase, family))
                self.assertEqual(len({r["id"] for r in rows}), size)
                seeds.update(r["seed"] for r in rows)
        self.assertEqual(len(seeds), 2 * sum(sizes.values()))
        native = windows_routed.plan("native", 4)
        self.assertEqual(sum(r["condition"] == "clean" for r in native), 12)
        self.assertEqual([r["condition"] for r in native[-3:]], ["drop"] * 3)
        null = windows_routed.plan("null", 6)
        self.assertEqual(sum(r["condition"] == "clean" for r in null), 60)
        self.assertTrue(all(r["expected"] == "no-difference" and r["sackopts"] == 0 for r in null))

    def test_seeds_do_not_reuse_earlier_registrations(self):
        earlier = set(range(66000, 68200)) | set(range(69000, 69720))  # through v1
        for phase in windows_routed.PHASES:
            for family in (4, 6):
                self.assertFalse({r["seed"] for r in windows_routed.plan(phase, family)} & earlier)

    def test_topology_is_routed_across_distinct_prefixes(self):
        for family in (4, 6):
            scope = windows_routed.topology(family)
            self.assertNotEqual(scope["source_prefix"], scope["target_prefix"])

    def test_router_truth_accepts_registered_conditions_only(self):
        for condition in ("clean", "drop"):
            state = windows_routed.parse_router(router_text(condition))
            self.assertEqual(windows_routed.validate_router(state, condition, "f1"), "f1")
            self.assertEqual(windows_routed.counter(state, 60065), 3)
        with self.assertRaisesRegex(ValueError, "condition"):
            windows_routed.validate_router(windows_routed.parse_router(router_text("drop")), "clean")
        widened = router_text("clean").replace("to 10.66.21.1 out", "to any out")
        with self.assertRaisesRegex(ValueError, "counter scope"):
            windows_routed.validate_router(windows_routed.parse_router(widened), "clean")
        extra = router_text("clean", "\n60070   0     0 allow ip from any to any")
        with self.assertRaisesRegex(ValueError, "registered set"):
            windows_routed.validate_router(windows_routed.parse_router(extra), "clean")
        with self.assertRaisesRegex(ValueError, "dummynet"):
            windows_routed.validate_router(windows_routed.parse_router(router_text("clean", modules="ipfw.ko dummynet.ko")), "clean")
        with self.assertRaisesRegex(ValueError, "interface"):
            windows_routed.validate_router(windows_routed.parse_router(router_text("clean")), "clean", "f1", None, "vmx0")
        with self.assertRaisesRegex(ValueError, "truncated"):
            windows_routed.parse_router(router_text("clean").replace("--- end\n", ""))

    def test_feasibility_requires_every_reply_without_sack(self):
        def summary(family, **override):
            rows = [dict({"outcome": "no-difference", "treatment_sack": 0, "control_sack": 0}, **override)
                    for _ in windows_routed.plan("feasibility", family)]
            return {"phase": "feasibility", "family": family, "rows": rows}
        self.assertTrue(windows_routed.feasibility_pass([summary(4), summary(6)]))
        self.assertFalse(windows_routed.feasibility_pass([summary(4)]))
        self.assertFalse(windows_routed.feasibility_pass([summary(4), summary(6, treatment_sack=1)]))
        self.assertFalse(windows_routed.feasibility_pass([summary(4), summary(6, outcome="unresolved")]))
        self.assertFalse(windows_routed.feasibility_pass([summary(4), summary(6, error="invalid")]))

    def test_protocol_is_the_registered_file(self):
        self.assertEqual(windows_routed.PROTOCOL, json.loads((HERE / "windows-routed-protocol.json").read_text()))


if __name__ == "__main__":
    unittest.main()
