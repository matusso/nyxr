import unittest

import adaptive_eval


def row(roles, classification, packets=10, **statements):
    st = {"classification": {"value": classification, "coverage": "tested", "evidence": [f"{r}:run" for r in roles]}}
    for key, (value, coverage) in statements.items():
        evidence = {"tested": ["main:run"], "profile-inferred": ["profile:x"], "not-tested": []}[coverage]
        st[key.replace("_", "-")] = {"value": value, "coverage": coverage, "evidence": evidence}
    return {"stop": "sufficient", "packets": packets, "duration_ms": 1, "roles": roles, "curtailed": 0, "study_classification": classification,
            "statements": st, "ports": {"tcp/443": {"port": "tcp/443", "coverage": "tested", "roles": ["main"]}}, "profile": None}


STUDIES = [{"id": "shared-endpoint-v4-000", "truth": "shared-state", "roles": {"main": "", "null": "", "reverse": ""}},
           {"id": "independent-v4-000", "truth": "no-coupling", "roles": {"main": "", "same-port": ""}}]


def rows(adaptive_shared="shared-state", fixed_packets=100, curtailed_packets=40):
    fixed = {"shared-endpoint-v4-000": row(["main", "null", "reverse"], "shared-state", fixed_packets, direction=("symmetric", "tested")),
             "independent-v4-000": row(["main", "same-port"], "no-coupling", fixed_packets)}
    adaptive = {"shared-endpoint-v4-000": row(["main", "null"], adaptive_shared, curtailed_packets, direction=("untested", "not-tested")),
                "independent-v4-000": row(["main", "same-port"], "no-coupling", curtailed_packets)}
    return {"fixed": fixed, "adaptive": adaptive, "adaptive-curtailed": adaptive, "adaptive-refined": adaptive}


class AdaptiveEvalTest(unittest.TestCase):
    def test_study_names(self):
        m = adaptive_eval.STUDY.match("shared-path-v4-003")
        self.assertEqual((m["topology"], m["family"], m["index"]), ("shared-path", "v4", "003"))
        self.assertIsNone(adaptive_eval.STUDY.match("campaign-1"))

    def test_second_after_rounds_up(self):
        self.assertEqual(adaptive_eval.second_after("2026-10-23T13:59:59.123456789Z"), "2026-10-23T14:00:00Z")

    def test_gates_pass_and_count_counterexamples(self):
        result = adaptive_eval.evaluate(rows(), STUDIES, [])
        self.assertTrue(all(v for k, v in result["gates"].items() if k != "G4_profile_invalidation"))
        self.assertFalse(result["gates"]["G4_profile_invalidation"])  # no profile applications fails closed
        self.assertEqual(len([c for c in result["counterexamples"] if c["statement"] == "direction"]), 3)

    def test_accuracy_loss_fails(self):
        result = adaptive_eval.evaluate(rows(adaptive_shared="unresolved"), STUDIES, [])
        self.assertFalse(result["gates"]["G1_no_accuracy_loss"])

    def test_traffic_gate(self):
        result = adaptive_eval.evaluate(rows(fixed_packets=10, curtailed_packets=10), STUDIES, [])
        self.assertFalse(result["gates"]["G2_traffic"])

    def test_dishonest_coverage_fails(self):
        r = rows()
        r["adaptive"]["independent-v4-000"]["statements"]["classification"]["evidence"] = ["null:run"]
        self.assertFalse(adaptive_eval.evaluate(r, STUDIES, [])["gates"]["G3_honest_coverage"])
        r = rows()
        r["adaptive"]["shared-endpoint-v4-000"]["statements"]["direction"]["value"] = "symmetric"
        self.assertFalse(adaptive_eval.evaluate(r, STUDIES, [])["gates"]["G3_honest_coverage"])

    def test_profile_gates(self):
        inferred = row(["main", "null"], "shared-state", 20, direction=("symmetric", "profile-inferred"))
        wrong = row(["main", "null"], "shared-state", 20, direction=("one-way", "profile-inferred"))
        good = [{"profile": "p", "study": "shared-endpoint-v4-000", "same_topology": True, "valid": True, "row": inferred},
                {"profile": "p", "study": "independent-v4-000", "same_topology": False, "valid": False, "row": rows()["adaptive"]["independent-v4-000"]}]
        result = adaptive_eval.evaluate(rows(), STUDIES, good)
        self.assertTrue(result["gates"]["G4_profile_invalidation"] and result["gates"]["G5_profile_inference"])
        stale = [dict(good[1], valid=True)]
        self.assertFalse(adaptive_eval.evaluate(rows(), STUDIES, stale)["gates"]["G4_profile_invalidation"])
        bad = [dict(good[0], row=wrong)]
        self.assertFalse(adaptive_eval.evaluate(rows(), STUDIES, bad)["gates"]["G5_profile_inference"])


if __name__ == "__main__":
    unittest.main()
