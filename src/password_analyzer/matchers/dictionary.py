from pathlib import Path


Frequency = float | None

# Names of the datasets that needs to be normalized for comparison
NORMALIZED_CASE_DATASETS = {
    "names_brazil",
    "names_english",
    "surnames_brazil",
    "surnames_english",
}


def load_simple_dataset(path: Path, normalize_case: bool = False) -> tuple[set[str], dict[str, Frequency]]:
    # Load a dataset containing one value per line.
    entries: set[str] = set()
    frequencies: dict[str, Frequency] = {}

    with path.open("r", encoding="utf-8") as file:
        for line in file:
            value = line.strip()

            if not value:
                continue

            if normalize_case:
                value = value.casefold()

            entries.add(value)
            frequencies[value] = None

    return entries, frequencies


def load_tsv_dataset(
    path: Path,
    value_column: int,
    frequency_column: int,
    normalize_case: bool = False,
) -> tuple[set[str], dict[str, Frequency]]:
    # Load a TSV dataset containing values and frequencies.
    entries: set[str] = set()
    frequencies: dict[str, Frequency] = {}

    with path.open("r", encoding="utf-8") as file:
        for line_number, line in enumerate(file):
            columns = line.rstrip("\n").split("\t")

            if len(columns) <= max(value_column, frequency_column):
                continue

            if line_number == 0:
                continue

            value = columns[value_column].strip()

            if not value:
                continue

            if normalize_case:
                value = value.casefold()

            try:
                frequency = float(columns[frequency_column])
            except ValueError:
                frequency = None

            entries.add(value)
            frequencies[value] = frequency

    return entries, frequencies


def load_dataset(
    path: Path,
    value_column: int | None = None,
    frequency_column: int | None = None,
    dataset_name: str | None = None,
) -> tuple[set[str], dict[str, Frequency]]:
    # Load a dictionary dataset.
    # The comparison is normalized (case-insensitive) only for the
    # datasets listed in NORMALIZED_CASE_DATASETS.
    normalize_case = dataset_name in NORMALIZED_CASE_DATASETS

    if value_column is not None and frequency_column is not None:
        return load_tsv_dataset(
            path=path,
            value_column=value_column,
            frequency_column=frequency_column,
            normalize_case=normalize_case,
        )

    return load_simple_dataset(path, normalize_case=normalize_case)


def find_best_match(
    password: str,
    entries: set[str],
    frequencies: dict[str, Frequency],
    min_length: int = 3,
    normalize_case: bool = False,
) -> dict | None:
    """
    Find the best dictionary match contained in a password.

    Match priority:
    1. Exact match with the entire password.
    2. Match with known frequency.
    3. Highest frequency.
    4. Longest matching substring.

    Quando `normalize_case=True` (usado para os datasets de nomes e
    sobrenomes), a comparação é feita ignorando maiúsculas/minúsculas,
    mas os valores "start"/"end"/"length" retornados continuam se
    referindo à senha original (não normalizada), e o "value" retornado
    é o trecho original da senha (não o casefolded).
    """
    best_match: dict | None = None

    search_password = password.casefold() if normalize_case else password

    # Check for an exact password match first.
    if search_password in entries:
        frequency = frequencies.get(search_password)

        return {
            "value": password,
            "frequency": frequency,
            "length": len(password),
            "start": 0,
            "end": len(password),
            "match_type": "exact",
        }

    # Search for substring matches.
    for start in range(len(password)):
        for end in range(start + min_length, len(password) + 1):
            substring = password[start:end]
            search_substring = substring.casefold() if normalize_case else substring

            if search_substring not in entries:
                continue

            frequency = frequencies.get(search_substring)

            current_match = {
                "value": substring,
                "frequency": frequency,
                "length": len(substring),
                "start": start,
                "end": end,
                "match_type": "substring",
            }

            if best_match is None:
                best_match = current_match
                continue

            current_has_frequency = frequency is not None
            best_has_frequency = best_match["frequency"] is not None

            # Prefer matches with known frequency.
            if current_has_frequency and not best_has_frequency:
                best_match = current_match
                continue

            if not current_has_frequency and best_has_frequency:
                continue

            # Both matches have frequency information.
            if current_has_frequency and best_has_frequency:
                if frequency > best_match["frequency"]:
                    best_match = current_match
                    continue

                if (
                    frequency == best_match["frequency"]
                    and current_match["length"] > best_match["length"]
                ):
                    best_match = current_match

                continue

            # Neither match has frequency information.
            if current_match["length"] > best_match["length"]:
                best_match = current_match

    return best_match
