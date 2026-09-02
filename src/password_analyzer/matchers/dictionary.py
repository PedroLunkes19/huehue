from pathlib import Path


Frequency = float | None


def load_simple_dataset(path: Path) -> tuple[set[str], dict[str, Frequency]]:
    # Load a dataset containing one value per line.
    entries: set[str] = set()
    frequencies: dict[str, Frequency] = {}

    with path.open("r", encoding="utf-8") as file:
        for line in file:
            value = line.strip()

            if not value:
                continue

            entries.add(value)
            frequencies[value] = None

    return entries, frequencies


def load_tsv_dataset(
    path: Path,
    value_column: int,
    frequency_column: int,
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

            try:
                frequency = float(columns[frequency_column])
            except ValueError:
                frequency = None

            entries.add(value)
            frequencies[value] = frequency

    return entries, frequencies


def load_dataset(path: Path, value_column: int | None = None, frequency_column: int | None = None) -> tuple[set[str], dict[str, Frequency]]:
    # Load a dictionary dataset.
    if value_column is not None and frequency_column is not None:
        return load_tsv_dataset(
            path=path,
            value_column=value_column,
            frequency_column=frequency_column,
        )

    return load_simple_dataset(path)


def find_best_match(
    password: str,
    entries: set[str],
    frequencies: dict[str, Frequency],
    min_length: int = 3,
) -> dict | None:
    """
    Find the best dictionary match contained in a password.

    Match priority:
    1. Exact match with the entire password.
    2. Match with known frequency.
    3. Highest frequency.
    4. Longest matching substring.
    """
    best_match: dict | None = None

    # Check for an exact password match first.
    if password in entries:
        frequency = frequencies.get(password)

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

            if substring not in entries:
                continue

            frequency = frequencies.get(substring)

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
