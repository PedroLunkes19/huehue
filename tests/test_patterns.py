import unittest

from password_analyzer.matchers import (
    find_date,
    find_patterns,
    find_repetition,
    find_keyboard_pattern,
)

from tests import (
    TEST_PASSWORD,
    TEST_PASSWORD_NOT_FOUND,
    TEST_PASSWORD_DATE,
    TEST_PASSWORD_DATE_SLASHES,
    TEST_PASSWORD_REPETITION,
    TEST_PASSWORD_SEQUENCE,
    TEST_PASSWORD_REVERSE_SEQUENCE,
    TEST_PASSWORD_UPPERCASE,
    TEST_PASSWORD_TRAILING_SPECIAL,
    TEST_PASSWORD_KEYBOARD,
    TEST_PASSWORD_KEYBOARD_REVERSE,
    TEST_PASSWORD_KEYBOARD_ZXCVBN,
)


class TestPatterns(unittest.TestCase):

    # ================================================================
    # DATE
    # ================================================================

    def test_date_without_slashes(self):

        result = find_date(
            TEST_PASSWORD_DATE,
        )

        self.assertIsNotNone(
            result,
        )

        print(
            f"\nSenha: {TEST_PASSWORD_DATE} | "
            f"Tipo: {result['match_type']} | "
            f"Padrão: {result['value']}"
        )

        self.assertEqual(
            result["match_type"],
            "date",
        )

        self.assertEqual(
            result["value"],
            TEST_PASSWORD_DATE[-8:],
        )

        self.assertEqual(
            len(result["value"]),
            8,
        )

        self.assertEqual(
            len(result["day"]),
            2,
        )

        self.assertEqual(
            len(result["month"]),
            2,
        )

        self.assertEqual(
            len(result["year"]),
            4,
        )

        self.assertTrue(
            result["day"].isdigit(),
        )

        self.assertTrue(
            result["month"].isdigit(),
        )

        self.assertTrue(
            result["year"].isdigit(),
        )

    def test_date_with_slashes(self):

        result = find_date(
            TEST_PASSWORD_DATE_SLASHES,
        )

        self.assertIsNotNone(
            result,
        )

        print(
            f"\nSenha: {TEST_PASSWORD_DATE_SLASHES} | "
            f"Tipo: {result['match_type']} | "
            f"Padrão: {result['value']}"
        )

        self.assertEqual(
            result["match_type"],
            "date",
        )

        self.assertEqual(
            result["value"],
            TEST_PASSWORD_DATE_SLASHES[-10:],
        )

        self.assertEqual(
            len(result["value"]),
            10,
        )

        self.assertEqual(
            len(result["day"]),
            2,
        )

        self.assertEqual(
            len(result["month"]),
            2,
        )

        self.assertEqual(
            len(result["year"]),
            4,
        )

        self.assertTrue(
            result["day"].isdigit(),
        )

        self.assertTrue(
            result["month"].isdigit(),
        )

        self.assertTrue(
            result["year"].isdigit(),
        )

    def test_date_not_found(self):

        result = find_date(
            TEST_PASSWORD_NOT_FOUND,
        )

        self.assertIsNone(
            result,
        )

    def test_date_structure(self):

        result = find_date(
            TEST_PASSWORD_DATE,
        )

        self.assertIsNotNone(
            result,
        )

        self.assertIn(
            "value",
            result,
        )

        self.assertIn(
            "day",
            result,
        )

        self.assertIn(
            "month",
            result,
        )

        self.assertIn(
            "year",
            result,
        )

        self.assertIn(
            "start",
            result,
        )

        self.assertIn(
            "end",
            result,
        )

        self.assertIn(
            "match_type",
            result,
        )

    # ================================================================
    # REPETITION
    # ================================================================

    def test_repetition_found(self):

        result = find_repetition(
            TEST_PASSWORD_REPETITION,
        )

        self.assertIsNotNone(
            result,
        )

        print(
            f"\nSenha: {TEST_PASSWORD_REPETITION} | "
            f"Tipo: {result['match_type']} | "
            f"Padrão: {result['value']}"
        )

        self.assertEqual(
            result["value"],
            "111",
        )

        self.assertEqual(
            result["character"],
            "1",
        )

        self.assertEqual(
            result["length"],
            3,
        )

        self.assertEqual(
            result["match_type"],
            "repetition",
        )

    def test_repetition_not_found(self):

        result = find_repetition(
            TEST_PASSWORD_NOT_FOUND,
        )

        self.assertIsNone(
            result,
        )

    def test_repetition_structure(self):

        result = find_repetition(
            TEST_PASSWORD_REPETITION,
        )

        self.assertIsNotNone(
            result,
        )

        self.assertIn(
            "value",
            result,
        )

        self.assertIn(
            "character",
            result,
        )

        self.assertIn(
            "length",
            result,
        )

        self.assertIn(
            "start",
            result,
        )

        self.assertIn(
            "end",
            result,
        )

        self.assertIn(
            "match_type",
            result,
        )

    # ================================================================
    # GENERAL PATTERNS
    # ================================================================

    def test_numeric_sequence(self):

        result = find_patterns(
            TEST_PASSWORD_SEQUENCE,
        )

        matches = [
            match
            for match in result
            if match["match_type"]
            == "numeric_sequence"
        ]

        self.assertGreater(
            len(matches),
            0,
        )

        for match in matches:

            print(
                f"\nSenha: {TEST_PASSWORD_SEQUENCE} | "
                f"Tipo: {match['match_type']} | "
                f"Padrão: {match['value']}"
            )

        self.assertEqual(
            matches[0]["value"],
            "123",
        )

    def test_reverse_numeric_sequence(self):

        result = find_patterns(
            TEST_PASSWORD_REVERSE_SEQUENCE,
        )

        matches = [
            match
            for match in result
            if match["match_type"]
            == "numeric_sequence"
        ]

        self.assertGreater(
            len(matches),
            0,
        )

        for match in matches:

            print(
                f"\nSenha: {TEST_PASSWORD_REVERSE_SEQUENCE} | "
                f"Tipo: {match['match_type']} | "
                f"Padrão: {match['value']}"
            )

        self.assertEqual(
            matches[0]["value"],
            "321",
        )

    def test_first_character_only_uppercase(self):

        result = find_patterns(
            TEST_PASSWORD_UPPERCASE,
        )

        matches = [
            match
            for match in result
            if match["match_type"]
            == "first_character_only_uppercase"
        ]

        self.assertGreater(
            len(matches),
            0,
        )

        for match in matches:

            print(
                f"\nSenha: {TEST_PASSWORD_UPPERCASE} | "
                f"Tipo: {match['match_type']} | "
                f"Padrão: {match['value']}"
            )

        self.assertEqual(
            matches[0]["value"],
            "M",
        )

    def test_multiple_uppercase_characters_not_detected(self):

        result = find_patterns(
            TEST_PASSWORD_NOT_FOUND.upper(),
        )

        matches = [
            match
            for match in result
            if match["match_type"]
            == "first_character_only_uppercase"
        ]

        self.assertEqual(
            matches,
            [],
        )

    def test_trailing_numbers(self):

        result = find_patterns(
            TEST_PASSWORD,
        )

        matches = [
            match
            for match in result
            if match["match_type"]
            == "trailing_numbers_or_special"
        ]

        self.assertGreater(
            len(matches),
            0,
        )

        for match in matches:

            print(
                f"\nSenha: {TEST_PASSWORD} | "
                f"Tipo: {match['match_type']} | "
                f"Padrão: {match['value']}"
            )

        self.assertEqual(
            matches[0]["value"],
            "123",
        )

    def test_trailing_numbers_and_special_characters(self):

        result = find_patterns(
            TEST_PASSWORD_TRAILING_SPECIAL,
        )

        matches = [
            match
            for match in result
            if match["match_type"]
            == "trailing_numbers_or_special"
        ]

        self.assertGreater(
            len(matches),
            0,
        )

        for match in matches:

            print(
                f"\nSenha: {TEST_PASSWORD_TRAILING_SPECIAL} | "
                f"Tipo: {match['match_type']} | "
                f"Padrão: {match['value']}"
            )

        self.assertEqual(
            matches[0]["value"],
            "123!",
        )

    def test_patterns_not_found(self):

        result = find_patterns(
            TEST_PASSWORD_NOT_FOUND,
        )

        self.assertEqual(
            result,
            [],
        )

    def test_pattern_structure(self):

        result = find_patterns(
            TEST_PASSWORD_TRAILING_SPECIAL,
        )
    
        self.assertGreater(
            len(result),
            0,
        )
    
        for match in result:
        
            self.assertIn(
                "value",
                match,
            )
    
            self.assertIn(
                "match_type",
                match,
            )

    # ================================================================
    # KEYBOARD
    # ================================================================

    def test_keyboard_qwerty(self):

        result = find_keyboard_pattern(
            TEST_PASSWORD_KEYBOARD,
        )

        self.assertIsNotNone(
            result,
        )

        print(
            f"\nSenha: {TEST_PASSWORD_KEYBOARD} | "
            f"Tipo: {result['match_type']} | "
            f"Padrão: {result['value']}"
        )

        self.assertEqual(
            result["value"],
            "qwerty",
        )

        self.assertEqual(
            result["length"],
            6,
        )

        self.assertEqual(
            result["direction"],
            "forward",
        )

        self.assertEqual(
            result["match_type"],
            "keyboard_pattern",
        )

    def test_keyboard_zxcvbn(self):

        result = find_keyboard_pattern(
            TEST_PASSWORD_KEYBOARD_ZXCVBN,
        )

        self.assertIsNotNone(
            result,
        )

        print(
            f"\nSenha: {TEST_PASSWORD_KEYBOARD_ZXCVBN} | "
            f"Tipo: {result['match_type']} | "
            f"Padrão: {result['value']}"
        )

        self.assertEqual(
            result["value"],
            "zxcvbn",
        )

        self.assertEqual(
            result["length"],
            6,
        )

        self.assertEqual(
            result["match_type"],
            "keyboard_pattern",
        )

    def test_keyboard_reverse(self):

        result = find_keyboard_pattern(
            TEST_PASSWORD_KEYBOARD_REVERSE,
        )

        self.assertIsNotNone(
            result,
        )

        print(
            f"\nSenha: {TEST_PASSWORD_KEYBOARD_REVERSE} | "
            f"Tipo: {result['match_type']} | "
            f"Padrão: {result['value']}"
        )

        self.assertEqual(
            result["value"],
            "ytrewq",
        )

        self.assertEqual(
            result["length"],
            6,
        )

        self.assertEqual(
            result["direction"],
            "backward",
        )

        self.assertEqual(
            result["match_type"],
            "keyboard_pattern",
        )

    def test_keyboard_not_found(self):

        result = find_keyboard_pattern(
            TEST_PASSWORD_NOT_FOUND,
        )

        self.assertIsNone(
            result,
        )

    def test_keyboard_structure(self):

        result = find_keyboard_pattern(
            TEST_PASSWORD_KEYBOARD,
        )

        self.assertIsNotNone(
            result,
        )

        self.assertIn(
            "value",
            result,
        )

        self.assertIn(
            "length",
            result,
        )

        self.assertIn(
            "start",
            result,
        )

        self.assertIn(
            "end",
            result,
        )

        self.assertIn(
            "direction",
            result,
        )

        self.assertIn(
            "match_type",
            result,
        )


if __name__ == "__main__":
    unittest.main()
