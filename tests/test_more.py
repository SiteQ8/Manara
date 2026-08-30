import contextlib
import io
import unittest

from manara import bruteforce, encoding, headers
from manara.cli import main
from manara.lessons import BY_ID, LESSONS


class TestEncoding(unittest.TestCase):
    def test_base64_roundtrip(self):
        self.assertEqual(encoding.b64_decode(encoding.b64_encode("attack at dawn")), "attack at dawn")

    def test_caesar_reverses(self):
        self.assertEqual(encoding.caesar(encoding.caesar("Hello, World", 3), -3), "Hello, World")

    def test_xor_reverses_with_same_key(self):
        h = encoding.xor_hex("secret message", "key")
        self.assertEqual(encoding.xor_from_hex(h, "key"), "secret message")

    def test_xor_is_not_plaintext(self):
        self.assertNotEqual(encoding.xor_hex("hello", "key"), "hello")


class TestHeaders(unittest.TestCase):
    def test_empty_is_unprotected(self):
        r = headers.check({})
        self.assertEqual(r["protected_pct"], 0)
        self.assertEqual(len(r["missing"]), len(headers.CATALOG))

    def test_all_present_is_full(self):
        good = {name: v[2] for name, v in headers.CATALOG.items()}
        r = headers.check(good)
        self.assertEqual(r["protected_pct"], 100)

    def test_case_insensitive(self):
        r = headers.check({"content-security-policy": "default-src 'self'"})
        names = [p["name"] for p in r["present"]]
        self.assertIn("Content-Security-Policy", names)


class TestBruteforce(unittest.TestCase):
    def test_space(self):
        self.assertEqual(bruteforce.space_size(4, 10), 10000)

    def test_lockout_makes_it_far_slower(self):
        r = bruteforce.simulate_pin("9999", lockout_after=3, lockout_seconds=300,
                                    online_guesses_per_second=10)
        self.assertEqual(r["tries"], 10000)
        self.assertGreater(r["seconds_with_lockout"], r["seconds_no_limit"] * 100)

    def test_found_in_order(self):
        r = bruteforce.simulate_pin("0005", online_guesses_per_second=10)
        self.assertEqual(r["tries"], 6)


class TestLessonsAndCli(unittest.TestCase):
    def test_every_lesson_has_text_and_takeaway(self):
        self.assertGreaterEqual(len(LESSONS), 11)
        for lesson in LESSONS:
            self.assertTrue(lesson.explanation.strip())
            self.assertTrue(lesson.takeaway.strip())
            self.assertTrue(lesson.title and lesson.summary)

    def test_list_runs(self):
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = main(["list", "--no-color"])
        self.assertEqual(rc, 0)
        for lesson in LESSONS:
            self.assertIn(lesson.id, buf.getvalue())

    def test_every_lesson_learns_cleanly(self):
        for lesson_id in BY_ID:
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                rc = main(["learn", lesson_id, "--no-color"])
            self.assertEqual(rc, 0, lesson_id)
            self.assertIn("Takeaway", buf.getvalue())

    def test_unknown_lesson_errors(self):
        rc = main(["learn", "nope", "--no-color"])
        self.assertEqual(rc, 2)


if __name__ == "__main__":
    unittest.main()
