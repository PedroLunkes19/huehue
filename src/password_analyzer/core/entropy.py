"""
Guess estimation for each match pattern.

Based on:
    - zxcvbn (scoring.coffee): guess estimation per pattern.
    - nbvcxz (BruteForceUtil): brute force cardinality from character sets.

All guess values are Python integers, so very large search spaces never
overflow (floats would break above ~1e308).
"""

import math
import re
from datetime import date

from ..models.result import Match


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Fallback brute force cardinality when a match carries none (zxcvbn uses 10).
BRUTEFORCE_CARDINALITY = 10

# A sub-match (one that does not cover the whole password) never costs fewer
# guesses than this. Prevents tiny matches from making a password look weak.
MIN_SUBMATCH_GUESSES_SINGLE_CHAR = 10
MIN_SUBMATCH_GUESSES_MULTI_CHAR = 50

MIN_YEAR_SPACE = 20
REFERENCE_YEAR = date.today().year

# QWERTY keyboard statistics, as computed by zxcvbn from its adjacency graph.
KEYBOARD_STARTING_POSITIONS = 47
KEYBOARD_AVERAGE_DEGREE = 4.595744680851064

START_UPPER = re.compile(r"^[A-Z][^A-Z]+$")
END_UPPER = re.compile(r"^[^A-Z]+[A-Z]$")
ALL_UPPER = re.compile(r"^[^a-z]+$")
ALL_LOWER = re.compile(r"^[^A-Z]+$")

# Datasets whose file order is NOT a popularity order (so a line position
# says nothing about how likely an entry is). For them the rank is the
# dataset size: the attacker would have to try the whole list.
UNORDERED_DATASETS = {"eff_large"}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def log10(value: int | float) -> float:
    # math.log10 supports arbitrarily large ints.
    return math.log10(value)


def log2(value: int | float) -> float:
    return math.log2(value)


def guesses_to_entropy_bits(guesses: int | float) -> float:
    """Entropy in bits equivalent to a number of guesses (log2)."""
    return log2(max(guesses, 1))


def bruteforce_cardinality(text: str) -> int:
    """
    Size of the character pool needed to brute force `text`, summing the
    pools actually used (nbvcxz BruteForceUtil):

        lowercase a-z   -> 26
        uppercase A-Z   -> 26
        digits          -> 10
        ASCII symbols   -> 33 (including space)
        anything else   -> 100 (accents, other alphabets, ...)
    """
    lower = upper = digits = symbols = other = False

    for character in text:
        if "a" <= character <= "z":
            lower = True
        elif "A" <= character <= "Z":
            upper = True
        elif "0" <= character <= "9":
            digits = True
        elif character.isascii() and character.isprintable():
            symbols = True
        else:
            other = True

    return (
        26 * lower
        + 26 * upper
        + 10 * digits
        + 33 * symbols
        + 100 * other
    )


# ---------------------------------------------------------------------------
# Rank tables (dictionary matches)
# ---------------------------------------------------------------------------

def build_rank_tables(datasets: dict) -> dict:
    """
    Build {dataset_name: {"ranks": {entry: rank}, "size": n, "ordered": bool}}.

    The loaders keep the file order inside the `frequencies` dict (dicts are
    insertion ordered), and every dataset is sorted from most to least
    common, so the line position is the rank (1 = most common).
    """
    tables = {}

    for name, dataset in datasets.items():
        frequencies = dataset["frequencies"]

        tables[name] = {
            "ranks": {
                entry: position
                for position, entry in enumerate(frequencies, start=1)
            },
            "size": len(frequencies),
            "ordered": name not in UNORDERED_DATASETS,
        }

    return tables


# ---------------------------------------------------------------------------
# Per-pattern estimators
# ---------------------------------------------------------------------------

def bruteforce_guesses(match: Match) -> int:
    cardinality = match.cardinality or BRUTEFORCE_CARDINALITY
    guesses = cardinality ** len(match.token)

    # One more than the smallest allowed sub-match guesses, so that
    # non-bruteforce matches over the same span take precedence.
    min_guesses = (
        MIN_SUBMATCH_GUESSES_SINGLE_CHAR + 1
        if len(match.token) == 1
        else MIN_SUBMATCH_GUESSES_MULTI_CHAR + 1
    )

    return max(guesses, min_guesses)


def uppercase_variations(word: str) -> int:
    if ALL_LOWER.match(word) or word.lower() == word:
        return 1

    # Capitalized, all caps and end-capitalized are common schemes:
    # underestimated as a 2x factor to be safe.
    for regex in (START_UPPER, END_UPPER, ALL_UPPER):
        if regex.match(word):
            return 2

    # Otherwise count the ways to capitalize U+L letters with U (or fewer)
    # uppercase letters; the mirrored case when lowercase is the minority.
    upper = sum(1 for c in word if "A" <= c <= "Z")
    lower = sum(1 for c in word if "a" <= c <= "z")

    return sum(math.comb(upper + lower, i) for i in range(1, min(upper, lower) + 1))


def dictionary_guesses(match: Match) -> int:
    match.base_guesses = match.rank
    match.uppercase_variations = uppercase_variations(match.token)

    return match.base_guesses * match.uppercase_variations


def repeat_guesses(match: Match) -> int:
    return match.base_guesses * match.repeat_count


def sequence_guesses(match: Match) -> int:
    first = match.token[0]

    # Lower guesses for obvious starting points.
    if first in ("a", "A", "z", "Z", "0", "1", "9"):
        base_guesses = 4
    elif first.isdigit():
        base_guesses = 10
    else:
        base_guesses = 26

    # A descending sequence must be tried in addition to the ascending one.
    if not match.ascending:
        base_guesses *= 2

    return base_guesses * len(match.token)


def spatial_guesses(match: Match) -> int:
    s = KEYBOARD_STARTING_POSITIONS
    d = KEYBOARD_AVERAGE_DEGREE
    length = len(match.token)
    turns = match.turns

    # Number of possible patterns of length L or less with t turns or less.
    guesses = 0.0

    for i in range(2, length + 1):
        possible_turns = min(turns, i - 1)

        for j in range(1, possible_turns + 1):
            guesses += math.comb(i - 1, j - 1) * s * (d ** j)

    # Extra guesses for shifted keys (uppercase letters).
    if match.shifted_count:
        shifted = match.shifted_count
        unshifted = length - shifted

        if unshifted == 0:
            guesses *= 2
        else:
            variations = sum(
                math.comb(shifted + unshifted, i)
                for i in range(1, min(shifted, unshifted) + 1)
            )
            guesses *= variations

    # round first: float accumulation noise must not push ceil() up by one.
    return math.ceil(round(guesses, 6))


def date_guesses(match: Match) -> int:
    # year distance from the reference year * number of days in a year
    year_space = max(abs(match.year - REFERENCE_YEAR), MIN_YEAR_SPACE)
    guesses = year_space * 365

    # Factor of 4 for the separator choice.
    if match.separator:
        guesses *= 4

    return guesses


_ESTIMATORS = {
    "bruteforce": bruteforce_guesses,
    "dictionary": dictionary_guesses,
    "spatial": spatial_guesses,
    "repeat": repeat_guesses,
    "sequence": sequence_guesses,
    "date": date_guesses,
}


def estimate_guesses(match: Match, password: str) -> int:
    """Number of guesses an attacker needs for `match` (cached in the match)."""
    if match.guesses is not None:
        return match.guesses

    min_guesses = 1

    if len(match.token) < len(password):
        min_guesses = (
            MIN_SUBMATCH_GUESSES_SINGLE_CHAR
            if len(match.token) == 1
            else MIN_SUBMATCH_GUESSES_MULTI_CHAR
        )

    guesses = _ESTIMATORS[match.pattern](match)

    match.guesses = max(guesses, min_guesses)
    match.guesses_log10 = log10(match.guesses)

    return match.guesses


__all__ = [
    "bruteforce_cardinality",
    "build_rank_tables",
    "estimate_guesses",
    "guesses_to_entropy_bits",
    "uppercase_variations",
]
