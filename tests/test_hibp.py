import unittest

from password_analyzer.api.hibp import check_password


class TestHIBP(unittest.TestCase):

    def test_password_found(self):

        password = "ADD PASSWORD HERE"

        result = check_password(password)

        self.assertTrue(result["found"])
        self.assertGreater(result["count"], 0)

        print(
            f"\nSenha encontrada {result['count']} vezes"
        )


    def test_response_structure(self):

        password = "ADD PASSWORD HERE"

        result = check_password(password)

        self.assertIn("found", result)
        self.assertIn("count", result)

        self.assertIsInstance(
            result["found"],
            bool
        )

        self.assertIsInstance(
            result["count"],
            int
        )


if __name__ == "__main__":
    unittest.main()