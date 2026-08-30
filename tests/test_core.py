import unittest

from manara import entropy, hashing, phishing, sqli


class TestHashing(unittest.TestCase):
    def test_deterministic(self):
        self.assertEqual(hashing.digest("hunter2"), hashing.digest("hunter2"))
        self.assertTrue(hashing.same_hash("abc", "abc"))
        self.assertFalse(hashing.same_hash("abc", "abd"))

    def test_known_sha256(self):
        # sha256("") is a fixed, well known value
        self.assertEqual(hashing.digest(""),
                         "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")

    def test_dictionary_attack_finds_common(self):
        h = hashing.digest("password")
        res = hashing.dictionary_attack(h)
        self.assertEqual(res["found"], "password")

    def test_salt_defeats_plain_wordlist(self):
        salted = hashing.salted_digest("password", "xyz123")
        res = hashing.dictionary_attack(salted, salt=None)
        self.assertIsNone(res["found"])
        # but with the salt known, it falls again
        res2 = hashing.dictionary_attack(salted, salt="xyz123")
        self.assertEqual(res2["found"], "password")


class TestEntropy(unittest.TestCase):
    def test_charset(self):
        self.assertEqual(entropy.charset_size("abc"), 26)
        self.assertEqual(entropy.charset_size("abcABC123"), 62)
        self.assertGreater(entropy.charset_size("abc!"), 26)

    def test_length_beats_complexity(self):
        short_complex = entropy.entropy_bits("P@ss1!")
        long_simple = entropy.entropy_bits("correct horse battery staple")
        self.assertGreater(long_simple, short_complex)

    def test_estimate_shape(self):
        e = entropy.estimate("hunter2")
        self.assertIn("entropy_bits", e)
        self.assertIn(e["label"], ["very weak", "weak", "reasonable", "strong", "very strong"])
        self.assertIsInstance(e["crack_time"], str)

    def test_empty(self):
        self.assertEqual(entropy.entropy_bits(""), 0.0)


class TestPhishing(unittest.TestCase):
    def test_legit_domain_ok(self):
        r = phishing.analyze("https://www.paypal.com/account")
        self.assertEqual(r["verdict"], "looks ok")
        self.assertEqual(r["registered_domain"], "paypal.com")

    def test_brand_in_subdomain_flagged(self):
        r = phishing.analyze("http://paypal.com.secure-login.ru/verify")
        self.assertEqual(r["verdict"], "suspicious")
        self.assertEqual(r["registered_domain"], "secure-login.ru")

    def test_at_trick_flagged(self):
        r = phishing.analyze("http://paypal.com@evil.example/login")
        titles = [s["title"] for s in r["signals"]]
        self.assertTrue(any("@" in t for t in titles))
        self.assertEqual(r["verdict"], "suspicious")

    def test_ip_literal_flagged(self):
        r = phishing.analyze("http://192.168.0.5/reset")
        self.assertEqual(r["verdict"], "suspicious")

    def test_lookalike_digit(self):
        r = phishing.analyze("https://paypa1.com/login")
        self.assertEqual(r["verdict"], "suspicious")


class TestSqli(unittest.TestCase):
    def test_injection_bypasses_vulnerable_login(self):
        r = sqli.vulnerable_login("admin", sqli.CLASSIC_PAYLOAD)
        self.assertTrue(r["granted"])
        self.assertIn("OR", r["query"].upper())

    def test_parameterized_login_is_safe(self):
        r = sqli.safe_login("admin", sqli.CLASSIC_PAYLOAD)
        self.assertFalse(r["granted"])

    def test_real_credentials_still_work_both_ways(self):
        self.assertTrue(sqli.vulnerable_login("admin", "s3cr3t-admin-pw")["granted"])
        self.assertTrue(sqli.safe_login("admin", "s3cr3t-admin-pw")["granted"])

    def test_wrong_password_denied(self):
        self.assertFalse(sqli.vulnerable_login("admin", "nope")["granted"])
        self.assertFalse(sqli.safe_login("admin", "nope")["granted"])


if __name__ == "__main__":
    unittest.main()
