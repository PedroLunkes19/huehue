import re
from typing import Optional


RepetitionMatch = Optional[dict]


def find_repetition(
    password: str,
    min_length: int = 3,
) -> RepetitionMatch:
    """
    Find repeated consecutive characters in a password.

    Example:
        senha111 -> 111
        abcaaaa -> aaaa

    Args:
        password: Password to analyze.
        min_length: Minimum number of repeated characters.

    Returns:
        A dictionary containing the repetition,
        or None if no repetition is found.
    """
    if min_length < 2:
        raise ValueError(
            "min_length must be at least 2"
        )

    pattern = re.compile(
        rf"(?P<character>.)"
        rf"(?P=character){{{min_length - 1},}}"
    )

    match = pattern.search(password)

    if match is None:
        return None

    value = match.group(0)

    return {
        "value": value,
        "character": match.group("character"),
        "length": len(value),
        "start": match.start(),
        "end": match.end(),
        "match_type": "repetition",
    }


__all__ = [
    "find_repetition",
]