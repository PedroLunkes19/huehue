import re


RepetitionMatch = dict | None


def find_repetition(password: str, min_length: int = 3) -> RepetitionMatch:
    """
    Find a consecutive repetition of the same character in a password.

    The repetition must contain at least min_length consecutive occurrences of the same character.

    Examples:
        senha123 -> no repetition
        senha111 -> 111
        passaaa123 -> aaa
        senha!!!! -> !!!!

    Args:
        password: Password to analyze.
        min_length: Minimum number of consecutive identical
            characters required to consider a repetition.

    Returns:
        A dictionary containing the detected repetition,
        or None if no repetition is found.
    """
    if min_length < 2:
        raise ValueError("min_length must be at least 2")

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
