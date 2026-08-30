import unittest

from manara import quiz, xss
from manara.lessons import BY_ID


class TestXss(unittest.TestCase):
    def test_script_would_execute(self):
        r = xss.render_unsafe("<script>alert(1)</script>")
        self.assertTrue(r["would_execute"])
        self.assertTrue(r["triggers"])

    def test_event_handler_would_execute(self):
        r = xss.render_unsafe('<img src=x onerror="bad()">')
        self.assertTrue(r["would_execute"])

    def test_plain_text_is_safe(self):
        r = xss.render_unsafe("Nice article, thanks!")
        self.assertFalse(r["would_execute"])
        self.assertEqual(r["triggers"], [])

    def test_escaping_neutralizes(self):
        r = xss.render_safe("<script>alert(1)</script>")
        self.assertFalse(r["would_execute"])
        self.assertNotIn("<script>", r["inserted"])
        self.assertIn("&lt;script&gt;", r["inserted"])

    def test_escape_html_order(self):
        # ampersand must be escaped first, so &lt; does not become &amp;lt;
        self.assertEqual(xss.escape_html("<a>&"), "&lt;a&gt;&amp;")

    def test_javascript_uri_flagged(self):
        self.assertTrue(xss.would_execute("javascript:alert(1)"))


class TestQuiz(unittest.TestCase):
    def test_bank_is_well_formed(self):
        self.assertGreaterEqual(len(quiz.QUESTIONS), 12)
        for q in quiz.QUESTIONS:
            self.assertIn(q["lesson"], BY_ID, q["lesson"])
            self.assertGreaterEqual(len(q["options"]), 3)
            self.assertTrue(0 <= q["answer"] < len(q["options"]))
            self.assertTrue(q["why"].strip())

    def test_all_correct_scores_full(self):
        answers = [q["answer"] for q in quiz.QUESTIONS]
        g = quiz.grade(answers)
        self.assertEqual(g["score"], g["total"])

    def test_all_wrong_scores_zero(self):
        answers = [(q["answer"] + 1) % len(q["options"]) for q in quiz.QUESTIONS]
        g = quiz.grade(answers)
        self.assertEqual(g["score"], 0)

    def test_none_answers_count_wrong(self):
        g = quiz.grade([None] * len(quiz.QUESTIONS))
        self.assertEqual(g["score"], 0)
        self.assertEqual(len(g["results"]), len(quiz.QUESTIONS))

    def test_short_answer_list_is_handled(self):
        g = quiz.grade([quiz.QUESTIONS[0]["answer"]])
        self.assertEqual(g["score"], 1)
        self.assertEqual(g["total"], len(quiz.QUESTIONS))

    def test_every_lesson_has_a_question(self):
        covered = {q["lesson"] for q in quiz.QUESTIONS}
        for lesson_id in BY_ID:
            self.assertIn(lesson_id, covered, lesson_id)


if __name__ == "__main__":
    unittest.main()
