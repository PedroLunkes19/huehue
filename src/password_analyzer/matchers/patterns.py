import re
from typing import Optional


PatternMatch = dict


SEQUENCE_PATTERN = re.compile(
    r"(?P<sequence>"
    r"(?:"
    r"(?:012|123|234|345|456|567|678|789)"
    r"|"
    r"(?:987|876|765|654|543|432|321|210)"
    r")"
    r")"
)


def find_numeric_sequence(
    password: str,
) -> Optional[PatternMatch]:
    """
    Find an ascending or descending numeric sequence.

    Examples:
        senha123 -> 123
        senha321 -> 321
        abc456xyz -> 456
        senha987 -> 987

    Returns:
        A dictionary containing the sequence,
        or None if no sequence is found.
    """
    match = SEQUENCE_PATTERN.search(password)

    if match is None:
        return None

    value = match.group("sequence")

    return {
        "value": value,
        "length": len(value),
        "start": match.start(),
        "end": match.end(),
        "match_type": "numeric_sequence",
    }


def find_first_character_uppercase(
    password: str,
) -> Optional[PatternMatch]:
    """
    Check whether the first character is the only uppercase
    character in the password.

    Examples:
        Senha123 -> detected
        Senha123! -> detected
        SENHA123 -> not detected
        senha123 -> not detected
        SenhaTeste123 -> not detected

    Returns:
        A dictionary describing the pattern,
        or None if the pattern is not found.
    """
    if not password:
        return None

    if not password[0].isupper():
        return None

    uppercase_characters = [
        character
        for character in password
        if character.isupper()
    ]

    if len(uppercase_characters) != 1:
        return None

    return {
        "value": password[0],
        "position": 0,
        "match_type": "first_character_only_uppercase",
    }


def find_trailing_characters(
    password: str,
) -> Optional[PatternMatch]:
    """
    Find numeric or special characters at the end of a password.

    Examples:
        Senha123 -> 123
        Senha! -> !
        Senha123! -> 123!
        Senha!@# -> !@#

    Returns:
        A dictionary containing the trailing characters,
        or None if the password does not end with a number
        or special character.
    """
    match = re.search(
        r"(?P<trailing>[\d\W_]+)$",
        password,
    )

    if match is None:
        return None

    value = match.group("trailing")

    return {
        "value": value,
        "length": len(value),
        "start": match.start(),
        "end": match.end(),
        "match_type": "trailing_numbers_or_special",
    }


def find_patterns(
    password: str,
) -> list[PatternMatch]:
    """
    Find all known patterns in a password.

    Patterns detected:
        - numeric sequences
        - first character as the only uppercase character
        - numbers or special characters at the end

    Returns:
        A list containing all detected patterns.
    """
    patterns: list[PatternMatch] = []

    numeric_sequence = find_numeric_sequence(
        password=password,
    )

    if numeric_sequence is not None:
        patterns.append(numeric_sequence)

    first_character_uppercase = (
        find_first_character_uppercase(
            password=password,
        )
    )

    if first_character_uppercase is not None:
        patterns.append(first_character_uppercase)

    trailing_characters = find_trailing_characters(
        password=password,
    )

    if trailing_characters is not None:
        patterns.append(trailing_characters)

    return patterns


__all__ = [
    "find_numeric_sequence",
    "find_first_character_uppercase",
    "find_trailing_characters",
    "find_patterns",
]
