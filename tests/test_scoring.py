import math
import unittest

from password_analyzer.core import scoring
from password_analyzer.models.result import Match


class TestScore(unittest.TestCase):

    # Same boundaries as zxcvbn/nbvcxz (nbvcxz ScoreTest implies them).
    def test_guesses_to_score(self):
        cases = {
            428: 0,          # 1qazxsw2
            1_056: 1,        # p4ssword
            100_000: 1,      # correcthorsebatterystaple
            2_490: 1,        # helphere
            1e7: 2,
            1e9: 3,
            1_427_153_297_000: 4,  # helpimaliveinhere
        }

        for guesses, expected in cases.items():
            self.assertEqual(scoring.guesses_to_score(guesses), expected, guesses)

    def test_boundaries(self):
        self.assertEqual(scoring.guesses_to_score(1004), 0)
        self.assertEqual(scoring.guesses_to_score(1005), 1)
        self.assertEqual(scoring.guesses_to_score(1_000_004), 1)
        self.assertEqual(scoring.guesses_to_score(1_000_005), 2)


class TestTimes(unittest.TestCase):

    # Values from nbvcxz TimeEstimateTest ("correcthorsebatterystaple").
    def test_time_to_crack(self):
        guesses = 100_000
        self.assertEqual(scoring.time_to_crack(guesses, "OFFLINE_MD5"), 0)
        self.assertEqual(scoring.time_to_crack(guesses, "OFFLINE_BCRYPT_10"), 24)
        self.assertEqual(scoring.time_to_crack(guesses, "OFFLINE_BCRYPT_12"), 96)
        self.assertEqual(scoring.time_to_crack(guesses, "OFFLINE_BCRYPT_14"), 386)
        self.assertEqual(scoring.time_to_crack(guesses, "ONLINE_UNTHROTTLED"), 1000)
        self.assertEqual(scoring.time_to_crack(guesses, "ONLINE_THROTTLED"), 50000)

    def test_display_time(self):
        self.assertEqual(scoring.display_time(0.5), "menos de um segundo")
        self.assertEqual(scoring.display_time(1), "1 segundo")
        self.assertEqual(scoring.display_time(30), "30 segundos")
        self.assertEqual(scoring.display_time(120), "2 minutos")
        self.assertEqual(scoring.display_time(3600), "1 hora")
        self.assertEqual(scoring.display_time(86400 * 3), "3 dias")
        self.assertEqual(scoring.display_time(86400 * 31 * 2), "2 meses")
        self.assertEqual(scoring.display_time(86400 * 31 * 12 * 5), "5 anos")
        self.assertEqual(scoring.display_time(1e12), "séculos")

    def test_estimate_attack_times(self):
        result = scoring.estimate_attack_times(1e6)
        seconds = result["crack_times_seconds"]
        self.assertAlmostEqual(seconds["online_no_throttling_10_per_second"], 1e5)
        self.assertAlmostEqual(seconds["offline_fast_hashing_1e10_per_second"], 1e-4)
        self.assertEqual(
            result["crack_times_display"]["offline_fast_hashing_1e10_per_second"],
            "menos de um segundo",
        )

    def test_huge_guesses_do_not_overflow(self):
        result = scoring.estimate_attack_times(10 ** 400)
        self.assertTrue(
            all(math.isinf(v) for v in result["crack_times_seconds"].values())
        )


class TestSearch(unittest.TestCase):

    def test_empty_password(self):
        result = scoring.most_guessable_match_sequence("", [])
        self.assertEqual(result["guesses"], 1)
        self.assertEqual(result["sequence"], [])

    def test_bruteforce_only(self):
        result = scoring.most_guessable_match_sequence("xqzvjkpmw", [])
        self.assertEqual(len(result["sequence"]), 1)
        self.assertEqual(result["sequence"][0].pattern, "bruteforce")
        # 26^9 + 10^0
        self.assertEqual(result["guesses"], 26 ** 9 + 1)

    def test_whole_dictionary_match(self):
        match = Match("dictionary", "password", 0, 7, rank=2)
        result = scoring.most_guessable_match_sequence("password", [match])
        self.assertEqual(result["guesses"], 2 + 1)
        self.assertEqual(result["sequence"], [match])

    def test_match_plus_bruteforce_gap(self):
        match = Match("dictionary", "maria", 0, 4, rank=1)
        result = scoring.most_guessable_match_sequence("mariaqzx", [match])

        patterns = [m.pattern for m in result["sequence"]]
        self.assertEqual(patterns, ["dictionary", "bruteforce"])
        # 2! * (50 * 26^3) + D^(2-1), with D = 10000
        self.assertEqual(
            result["guesses"],
            2 * 50 * 26 ** 3 + scoring.MIN_GUESSES_BEFORE_GROWING_SEQUENCE,
        )

    def test_overlapping_matches_pick_cheapest(self):
        cheap = Match("dictionary", "pass", 0, 3, rank=1)
        expensive = Match("dictionary", "passw", 0, 4, rank=10 ** 9)
        result = scoring.most_guessable_match_sequence("passw", [cheap, expensive])
        self.assertIn(cheap, result["sequence"])
        self.assertNotIn(expensive, result["sequence"])

    def test_sequence_is_contiguous(self):
        password = "abc123xyz"
        matches = [Match("sequence", "123", 3, 5)]
        result = scoring.most_guessable_match_sequence(password, matches)
        self.assertEqual("".join(m.token for m in result["sequence"]), password)

    def test_bruteforce_scope(self):
        # The accented letter widens the pool of the whole password only.
        password = "mariéxqzv"
        matches = [Match("dictionary", "marié", 0, 4, rank=1)]
        token = scoring.most_guessable_match_sequence(password, matches, bruteforce_scope="token")
        whole = scoring.most_guessable_match_sequence(password, matches, bruteforce_scope="password")
        self.assertLess(token["guesses"], whole["guesses"])


if __name__ == "__main__":
    unittest.main()
