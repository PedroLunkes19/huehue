from pathlib import Path


from .dates import find_date
from .keyboard import find_keyboard_pattern
from .patterns import find_patterns
from .repetition import find_repetition
from .dictionary import find_best_match, load_dataset


DATA_DIRECTORY = Path(__file__).resolve().parent.parent / "data"


DATASETS = {
    "common_passwords": {
        "file": "common_passwords.txt",
        "priority": 1,
    },
    "names_brazil": {
        "file": "names_brazil.tsv",
        "value_column": 0,
        "frequency_column": 1,
        "priority": 2,
    },
    "names_english": {
        "file": "names_english.txt",
        "priority": 2,
    },
    "surnames_brazil": {
        "file": "surnames_brazil.tsv",
        "value_column": 1,
        "frequency_column": 2,
        "priority": 3,
    },
    "surnames_english": {
        "file": "surnames_english.txt",
        "priority": 3,
    },
    "eff_large": {
        "file": "eff_large.txt",
        "priority": 4,
    },
    "english": {
        "file": "english.txt",
        "priority": 4,
    },
}


# Load all configured dictionary datasets.
def load_datasets(data_directory: Path = DATA_DIRECTORY) -> dict:
    datasets = {}

    for dataset_name, configuration in DATASETS.items():
        path = data_directory / configuration["file"]

        entries, frequencies = load_dataset(
            path=path,
            value_column=configuration.get("value_column"),
            frequency_column=configuration.get("frequency_column"),
        )

        datasets[dataset_name] = {
            "entries": entries,
            "frequencies": frequencies,
            "priority": configuration["priority"],
        }

    return datasets


# Check a password against all dictionary datasets.
# All matches are returned and ordered by dataset priority.
def check_dictionary_matches(password: str, datasets: dict, min_length: int = 3) -> dict:
    matches = []

    for dataset_name, dataset in datasets.items():
        match = find_best_match(
            password=password,
            entries=dataset["entries"],
            frequencies=dataset["frequencies"],
            min_length=min_length,
        )

        if match is None:
            continue

        match["dataset"] = dataset_name
        match["priority"] = dataset["priority"]

        matches.append(match)

    matches.sort(key=lambda match: match["priority"])

    return {
        "present": bool(matches),
        "matches": matches,
    }


def match_password(password: str, datasets: dict, min_dictionary_length: int = 3, min_repetition_length: int = 3, min_keyboard_length: int = 3,) -> dict:
    """
    Run all password matchers against a password.

    Matchers:
        - dictionary
        - date
        - repetition
        - patterns
        - keyboard

    Args:
        password:
            Password to analyze.

        datasets:
            Loaded dictionary datasets.

        min_dictionary_length:
            Minimum length for dictionary matches.

        min_repetition_length:
            Minimum length for repeated characters.

        min_keyboard_length:
            Minimum length for keyboard patterns.

    Returns:
        A dictionary containing the result of every matcher.
    """
    return {
        "password": password,

        "dictionary": check_dictionary_matches(
            password=password,
            datasets=datasets,
            min_length=min_dictionary_length,
        ),

        "date": find_date(password=password),

        "repetition": find_repetition(
            password=password,
            min_length=min_repetition_length,
        ),

        "patterns": find_patterns(password=password),

        "keyboard": find_keyboard_pattern(
            password=password,
            min_length=min_keyboard_length,
        ),
    }


__all__ = [
    "DATA_DIRECTORY",
    "DATASETS",
    "load_datasets",
    "check_dictionary_matches",
    "match_password",
]
