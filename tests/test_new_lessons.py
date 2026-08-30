import unittest

from manara import sessions, tlscert, traffic


class TestSessions(unittest.TestCase):
    def test_session_ids_are_unique(self):
        self.assertNotEqual(sessions.new_session_id(), sessions.new_session_id())
        self.assertEqual(len(sessions.new_session_id()), 32)

    def test_no_flags_opens_all_three(self):
        r = sessions.analyze({})
        self.assertEqual(r["exposure"], 3)
        self.assertEqual(r["protected"], 0)

    def test_all_flags_close_everything(self):
        r = sessions.analyze({"HttpOnly": True, "Secure": True, "SameSite": True})
        self.assertEqual(r["exposure"], 0)
        self.assertEqual(r["protected"], 3)

    def test_missing_httponly_is_a_risk(self):
        r = sessions.analyze({"Secure": True, "SameSite": True})
        titles = " ".join(risk["title"] for risk in r["risks"]).lower()
        self.assertIn("script", titles)
        self.assertEqual(r["exposure"], 1)


class TestTls(unittest.TestCase):
    def test_valid_cert_is_trusted(self):
        sc = tlscert.SCENARIOS["valid"]
        r = tlscert.validate(sc["cert"], sc["hostname"], tlscert.TODAY)
        self.assertTrue(r["trusted"])
        self.assertTrue(all(c["ok"] for c in r["checks"]))

    def test_expired_cert_fails(self):
        sc = tlscert.SCENARIOS["expired"]
        r = tlscert.validate(sc["cert"], sc["hostname"], tlscert.TODAY)
        self.assertFalse(r["trusted"])
        failed = [c["name"] for c in r["checks"] if not c["ok"]]
        self.assertIn("Within its validity dates", failed)

    def test_wrong_hostname_fails(self):
        sc = tlscert.SCENARIOS["wrong_host"]
        r = tlscert.validate(sc["cert"], sc["hostname"], tlscert.TODAY)
        self.assertFalse(r["trusted"])

    def test_self_signed_fails_trust(self):
        sc = tlscert.SCENARIOS["self_signed"]
        r = tlscert.validate(sc["cert"], sc["hostname"], tlscert.TODAY)
        self.assertFalse(r["trusted"])

    def test_wildcard_match(self):
        cert = {"subject": "*.example.com", "issuer": "Global Root CA",
                "valid_from": "2025-01-01", "valid_to": "2026-06-01", "self_signed": False}
        r = tlscert.validate(cert, "shop.example.com", tlscert.TODAY)
        self.assertTrue(r["trusted"])
        # but a wildcard does not span two labels
        r2 = tlscert.validate(cert, "a.b.example.com", tlscert.TODAY)
        self.assertFalse(r2["trusted"])


class TestTraffic(unittest.TestCase):
    def test_scanner_detected(self):
        res = traffic.detect_port_scan(traffic.SAMPLE_LOG)
        self.assertEqual(len(res["scanners"]), 1)
        self.assertEqual(res["scanners"][0]["source"], "10.0.0.66")
        self.assertGreaterEqual(res["scanners"][0]["distinct_ports"], 15)

    def test_normal_hosts_not_flagged(self):
        res = traffic.detect_port_scan(traffic.SAMPLE_LOG)
        flagged = {s["source"] for s in res["scanners"]}
        self.assertNotIn("10.0.0.5", flagged)
        self.assertNotIn("10.0.0.7", flagged)

    def test_summary_sorted_by_spread(self):
        rows = traffic.summarize(traffic.SAMPLE_LOG)
        self.assertEqual(rows[0]["source"], "10.0.0.66")
        self.assertGreaterEqual(rows[0]["distinct_ports"], rows[1]["distinct_ports"])

    def test_threshold_respected(self):
        res = traffic.detect_port_scan(traffic.SAMPLE_LOG, port_threshold=100)
        self.assertEqual(len(res["scanners"]), 0)


if __name__ == "__main__":
    unittest.main()
