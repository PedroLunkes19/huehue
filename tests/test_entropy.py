import math
import unittest

from password_analyzer.core import entropy
from password_analyzer.models.result import Match


class TestBruteforceCardinality(unittest.TestCase):

    # Fixture adapted from nbvcxz BruteForceUtilTest.
    FIXTURE = {
        "abcdefghijklmnopqrstuvwxyz": 26,
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ": 26,
        "0123456789": 10,
        " !\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~": 33,
        "é": 100,
        "\u1234": 100,
        "aB": 52,
        "a1": 36,
        "a@": 59,
        "aé": 126,
        "0@": 43,
        "2é": 110,
        "@é": 133,
        "aB1": 62,
        "aB$": 85,
        "aBé": 152,
        "a1$": 69,
        "a5é": 136,
        "a@é": 159,
        "4_é": 143,
        "C4%é": 169,
        "Cs%é": 185,
        "Cs3é": 162,
        "Cs3_": 95,
        "aD3%é": 195,
    }

    def test_fixture(self):
        for password, expected in self.FIXTURE.items():
            self.assertEqual(
                entropy.bruteforce_cardinality(password),
                expected,
                password,
            )


class TestEstimators(unittest.TestCase):

    def test_uppercase_variations(self):
        self.assertEqual(entropy.uppercase_variations("maria"), 1)
        self.assertEqual(entropy.uppercase_variations("Maria"), 2)
        self.assertEqual(entropy.uppercase_variations("MARIA"), 2)
        self.assertEqual(entropy.uppercase_variations("mariA"), 2)
        # mArIa: U=2, L=3 -> C(5,1) + C(5,2) = 15
        self.assertEqual(entropy.uppercase_variations("mArIa"), 15)

    def test_dictionary_guesses(self):
        match = Match("dictionary", "Maria", 0, 4, rank=10)
        self.assertEqual(entropy.estimate_guesses(match, "Maria"), 20)

    def test_sequence_guesses(self):
        ascending = Match("sequence", "123", 0, 2, ascending=True)
        descending = Match("sequence", "321", 0, 2, ascending=False)
        self.assertEqual(entropy.estimate_guesses(ascending, "123"), 12)
        self.assertEqual(entropy.estimate_guesses(descending, "321"), 60)

    def test_repeat_guesses(self):
        match = Match("repeat", "aaaa", 0, 3, base_guesses=26, repeat_count=4)
        self.assertEqual(entropy.estimate_guesses(match, "aaaa"), 104)

    def test_date_guesses(self):
        plain = Match("date", "31122026", 0, 7, year=entropy.REFERENCE_YEAR)
        sep = Match("date", "31/12/2026", 0, 9, year=entropy.REFERENCE_YEAR, separator=True)
        self.assertEqual(entropy.estimate_guesses(plain, "31122026"), 20 * 365)
        self.assertEqual(entropy.estimate_guesses(sep, "31/12/2026"), 20 * 365 * 4)

    def test_spatial_guesses(self):
        match = Match("spatial", "qwerty", 0, 5, turns=1)
        expected = math.ceil(5 * entropy.KEYBOARD_STARTING_POSITIONS * entropy.KEYBOARD_AVERAGE_DEGREE)
        self.assertEqual(entropy.estimate_guesses(match, "qwerty"), expected)

    def test_submatch_minimum(self):
        match = Match("sequence", "123", 0, 2)
        # 12 guesses, but a sub-match costs at least 50.
        self.assertEqual(entropy.estimate_guesses(match, "abc123xyz"), 50)

    def test_bruteforce_guesses(self):
        match = Match("bruteforce", "abc", 0, 2, cardinality=26)
        self.assertEqual(entropy.estimate_guesses(match, "abc"), 26 ** 3)

    def test_entropy_bits(self):
        self.assertAlmostEqual(entropy.guesses_to_entropy_bits(1024), 10.0)


if __name__ == "__main__":
    unittest.main()
