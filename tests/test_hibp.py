import unittest

from password_analyzer.api.hibp import check_password

from tests import (
    TEST_PASSWORD,
)


class TestHIBP(unittest.TestCase):

    def test_password_found(self):

        result = check_password(
            TEST_PASSWORD,
        )

        self.assertTrue(
            result["found"],
        )

        self.assertGreater(
            result["count"],
            0,
        )

        print(
            f"\nSenha encontrada "
            f"{result['count']} vezes"
        )

    def test_response_structure(self):

        result = check_password(
            TEST_PASSWORD,
        )

        self.assertIn(
            "found",
            result,
        )

        self.assertIn(
            "count",
            result,
        )

        self.assertIsInstance(
            result["found"],
            bool,
        )

        self.assertIsInstance(
            result["count"],
            int,
        )


if __name__ == "__main__":
    unittest.main()
