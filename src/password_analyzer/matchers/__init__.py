from pathlib import Path

from .dictionary import (
    find_best_match,
    load_dataset,
)


DATA_DIRECTORY = Path(__file__).resolve().parent.parent / "data"


DATASETS = {
    "common_passwords": {
        "file": "common_passwords.txt",
        "priority": 1,
    },
    "eff_large": {
        "file": "eff_large.txt",
        "priority": 2,
    },
    "names_brazil": {
        "file": "names_brazil.tsv",
        "value_column": 0,
        "frequency_column": 1,
        "priority": 3,
    },
    "surnames_brazil": {
        "file": "surnames_brazil.tsv",
        "value_column": 1,
        "frequency_column": 2,
        "priority": 4,
    },
    "names_english": {
        "file": "names_english.txt",
        "priority": 5,
    },
    "surnames_english": {
        "file": "surnames_english.txt",
        "priority": 6,
    },
    "english": {
        "file": "english.txt",
        "priority": 7,
    },
}


def load_datasets(
    data_directory: Path = DATA_DIRECTORY,
) -> dict:
    """
    Load all configured dictionary datasets.
    """
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


def check_dictionary_matches(
    password: str,
    datasets: dict,
    min_length: int = 3,
) -> dict:
    """
    Check a password against all dictionary datasets.

    All matches are returned and ordered by dataset priority.

    Priority:
        1. common_passwords
        2. eff_large
        3. names_brazil
        4. surnames_brazil
        5. names_english
        6. surnames_english
        7. english

    Returns:
        {
            "present": bool,
            "matches": list
        }
    """
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

    matches.sort(
        key=lambda match: match["priority"]
    )

    return {
        "present": bool(matches),
        "matches": matches,
    }


__all__ = [
    "DATA_DIRECTORY",
    "DATASETS",
    "load_datasets",
    "check_dictionary_matches",
]