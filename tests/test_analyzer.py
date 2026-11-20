import unittest

from password_analyzer.core.analyzer import PasswordAnalyzer
from password_analyzer.matchers import load_datasets

from tests import (
    TEST_PASSWORD,
    TEST_PASSWORD_NOT_FOUND,
    TEST_PASSWORD_REPETITION,
    TEST_PASSWORD_KEYBOARD,
    TEST_PASSWORD_DATE,
)


def not_breached(password):
    return {"found": False, "count": 0}


def breached(password):
    return {"found": True, "count": 123}


class TestAnalyzer(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        # Datasets are loaded once; no test touches the network.
        cls.datasets = load_datasets()

    def analyzer(self, checker=not_breached):
        return PasswordAnalyzer(datasets=self.datasets, breach_checker=checker)

    def test_breached_password_scores_zero(self):
        result = self.analyzer(breached).analyze("Xq9#vLm2$wTz!rBn")

        self.assertEqual(result.score, 0)
        self.assertTrue(result.breached)
        self.assertEqual(result.breach_count, 123)
        # The local analysis is still reported.
        self.assertEqual(result.raw_score, 4)

    def test_blacklisted_password_scores_zero(self):
        result = self.analyzer().analyze("admin")
        self.assertTrue(result.blacklisted)
        self.assertEqual(result.score, 0)

    def test_common_password_is_weak(self):
        result = self.analyzer().analyze(TEST_PASSWORD)
        self.assertEqual(result.score, 1)
        self.assertLess(result.guesses, 10 ** 6)
        self.assertTrue(any(m.pattern == "dictionary" for m in result.sequence))

    def test_random_password_is_strong(self):
        result = self.analyzer().analyze("Xq9#vLm2$wTz!rBn")
        self.assertEqual(result.score, 4)
        self.assertEqual(result.raw_score, 4)

    def test_not_found_password(self):
        result = self.analyzer().analyze(TEST_PASSWORD_NOT_FOUND)
        self.assertGreaterEqual(result.score, 1)

    def test_score_never_zero_without_breach(self):
        result = self.analyzer().analyze("1qazxsw2")
        self.assertGreaterEqual(result.score, 1)

    def test_longer_password_scores_higher(self):
        short = self.analyzer().analyze("xqzvjk")
        long = self.analyzer().analyze("xqzvjkpmwhtbrcnl")
        self.assertGreater(long.guesses, short.guesses)

    def test_patterns_reduce_guesses(self):
        # Replacing random characters by a repetition must be cheaper.
        random_ = self.analyzer().analyze("maria" + "xqz")
        repeated = self.analyzer().analyze(TEST_PASSWORD_REPETITION)
        self.assertLess(repeated.guesses, random_.guesses)

    def test_keyboard_pattern_is_a_candidate_match(self):
        # The search may prefer a cheaper dictionary match (qwerty is a
        # very common password), but the keyboard match must be offered.
        matches = self.analyzer().build_matches(TEST_PASSWORD_KEYBOARD)
        self.assertIn("spatial", [m.pattern for m in matches])

    def test_multiple_dictionary_matches_per_dataset(self):
        # "help" and "here" are both found, not just the best one.
        matches = self.analyzer().build_matches("helphere")
        tokens = {m.token for m in matches if m.dataset == "english"}
        self.assertIn("help", tokens)
        self.assertIn("here", tokens)

    def test_date_pattern_detected(self):
        result = self.analyzer().analyze(TEST_PASSWORD_DATE)
        self.assertIn("date", [m.pattern for m in result.sequence])

    def test_breach_check_failure_is_not_fatal(self):
        import requests

        def failing(password):
            raise requests.ConnectionError("offline")

        result = self.analyzer(failing).analyze("Xq9#vLm2$wTz!rBn")
        self.assertIsNone(result.breached)
        self.assertEqual(result.score, 4)

    def test_breach_check_disabled(self):
        result = PasswordAnalyzer(datasets=self.datasets, breach_checker=None).analyze("abc")
        self.assertIsNone(result.breached)

    def test_composition_violations_reported(self):
        result = self.analyzer().analyze("abc")
        rules = [v["rule"] for v in result.rule_violations]
        self.assertIn("min_length", rules)

    def test_result_does_not_store_password(self):
        password = "Xq9#vLm2$wTz!rBn"
        result = self.analyzer().analyze(password)
        self.assertEqual(result.password_length, len(password))
        self.assertNotIn(password, str(result.to_dict().get("warnings")))

    def test_sequence_covers_whole_password(self):
        password = "Maria123!xyz"
        result = self.analyzer().analyze(password)
        self.assertEqual("".join(m.token for m in result.sequence), password)

    def test_empty_password(self):
        result = self.analyzer().analyze("")
        self.assertEqual(result.guesses, 1)

    def test_very_long_password_is_bounded(self):
        result = self.analyzer().analyze("aB3$" * 500)
        self.assertEqual(result.password_length, 2000)
        self.assertEqual(result.score, 4)


if __name__ == "__main__":
    unittest.main()
