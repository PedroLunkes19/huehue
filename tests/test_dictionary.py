import unittest

from password_analyzer.matchers import (
    load_datasets,
    check_dictionary_matches,
)

from tests import (
    TEST_PASSWORD,
    TEST_PASSWORD_NOT_FOUND,
)


class TestDictionary(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.datasets = load_datasets()

    def test_password_found(self):

        result = check_dictionary_matches(
            TEST_PASSWORD,
            self.datasets,
        )

        self.assertTrue(result["present"])
        self.assertGreater(
            len(result["matches"]),
            0,
        )

        best_match = result["matches"][0]

        self.assertEqual(
            best_match["dataset"],
            "common_passwords",
        )

        self.assertEqual(
            best_match["value"],
            TEST_PASSWORD,
        )

        print(
            f"\nMelhor match: "
            f"{best_match['value']} | "
            f"Dataset: {best_match['dataset']} | "
            f"Prioridade: {best_match['priority']} | "
            f"Frequência: {best_match['frequency']}"
        )

    def test_password_not_found(self):

        result = check_dictionary_matches(
            TEST_PASSWORD_NOT_FOUND,
            self.datasets,
        )

        self.assertFalse(result["present"])

        self.assertEqual(
            result["matches"],
            [],
        )

    def test_response_structure(self):

        result = check_dictionary_matches(
            TEST_PASSWORD,
            self.datasets,
        )

        self.assertIn(
            "present",
            result,
        )

        self.assertIn(
            "matches",
            result,
        )

        self.assertIsInstance(
            result["present"],
            bool,
        )

        self.assertIsInstance(
            result["matches"],
            list,
        )

    def test_match_structure(self):

        result = check_dictionary_matches(
            TEST_PASSWORD,
            self.datasets,
        )

        self.assertTrue(result["present"])

        for match in result["matches"]:

            self.assertIn(
                "dataset",
                match,
            )

            self.assertIn(
                "value",
                match,
            )

            self.assertIn(
                "frequency",
                match,
            )

            self.assertIn(
                "priority",
                match,
            )

            self.assertIn(
                "length",
                match,
            )

            self.assertIn(
                "start",
                match,
            )

            self.assertIn(
                "end",
                match,
            )

            self.assertIn(
                "match_type",
                match,
            )

    def test_match_priority(self):

        result = check_dictionary_matches(
            TEST_PASSWORD,
            self.datasets,
        )

        self.assertTrue(result["present"])

        priorities = [
            match["priority"]
            for match in result["matches"]
        ]

        self.assertEqual(
            priorities,
            sorted(priorities),
        )

        self.assertEqual(
            result["matches"][0]["dataset"],
            "common_passwords",
        )

    def test_all_relevant_datasets_are_returned(self):

        result = check_dictionary_matches(
            TEST_PASSWORD,
            self.datasets,
        )

        datasets = {
            match["dataset"]
            for match in result["matches"]
        }

        self.assertIn(
            "common_passwords",
            datasets,
        )

        self.assertIn(
            "names_brazil",
            datasets,
        )

        self.assertIn(
            "surnames_brazil",
            datasets,
        )

    def test_brazilian_name_frequency(self):

        result = check_dictionary_matches(
            TEST_PASSWORD,
            self.datasets,
        )

        brazilian_names = [
            match
            for match in result["matches"]
            if match["dataset"] == "names_brazil"
        ]

        self.assertGreater(
            len(brazilian_names),
            0,
        )

        match = brazilian_names[0]

        self.assertEqual(
            match["value"],
            "maria",
        )

        self.assertIsNotNone(
            match["frequency"],
        )

        self.assertGreater(
            match["frequency"],
            0,
        )


if __name__ == "__main__":
    unittest.main()