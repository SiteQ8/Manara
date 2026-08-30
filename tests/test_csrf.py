import unittest

from manara import csrf


class TestCsrf(unittest.TestCase):
    def test_legit_transfer_executes(self):
        r = csrf.attempt_transfer(cross_site=False, token=csrf.SERVER_TOKEN,
                                  csrf_protection=True, same_site_cookie=True)
        self.assertTrue(r["executed"])
        self.assertIsNone(r["blocked_by"])

    def test_forged_request_succeeds_with_no_defenses(self):
        r = csrf.attempt_transfer(cross_site=True, token=None,
                                  csrf_protection=False, same_site_cookie=False)
        self.assertTrue(r["executed"])
        self.assertTrue(r["cross_site"])

    def test_csrf_token_blocks_forgery(self):
        r = csrf.attempt_transfer(cross_site=True, token=None,
                                  csrf_protection=True, same_site_cookie=False)
        self.assertFalse(r["executed"])
        self.assertEqual(r["blocked_by"], "CSRF token")

    def test_samesite_blocks_forgery(self):
        r = csrf.attempt_transfer(cross_site=True, token=None,
                                  csrf_protection=False, same_site_cookie=True)
        self.assertFalse(r["executed"])
        self.assertEqual(r["blocked_by"], "SameSite cookie")
        self.assertFalse(r["cookie_sent"])

    def test_samesite_does_not_block_same_site_request(self):
        # a SameSite cookie is still sent on the site's own requests
        r = csrf.attempt_transfer(cross_site=False, token=csrf.SERVER_TOKEN,
                                  csrf_protection=True, same_site_cookie=True)
        self.assertTrue(r["cookie_sent"])

    def test_wrong_token_is_rejected(self):
        r = csrf.attempt_transfer(cross_site=True, token="guessed",
                                  csrf_protection=True, same_site_cookie=False)
        self.assertFalse(r["executed"])

    def test_all_scenarios_present(self):
        self.assertEqual(set(csrf.SCENARIOS), {"legit", "attack_open", "attack_vs_token", "attack_vs_samesite"})


if __name__ == "__main__":
    unittest.main()
