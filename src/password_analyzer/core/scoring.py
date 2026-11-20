"""
Scoring: most guessable match sequence, score (0-4) and crack time estimates.

Based on:
    - zxcvbn: most_guessable_match_sequence, guesses_to_score, display_time
      and estimate_attack_times.
    - nbvcxz: time to crack per configurable "guess type" (guesses/second).

The search minimizes:

    g = l! * Product(m.guesses for m in sequence) + D^(l - 1)

where l is the sequence length and D = MIN_GUESSES_BEFORE_GROWING_SEQUENCE.
 - the factorial term is the number of ways to order l patterns;
 - the D^(l-1) term is a length penalty: an attacker tries shorter sequences
   before longer ones.
"""

import math

from ..models.result import Match
from .entropy import (
    bruteforce_cardinality,
    estimate_guesses,
    log10,
)


MIN_GUESSES_BEFORE_GROWING_SEQUENCE = 10000

# Score thresholds (guesses). DELTA avoids edge effects at exact powers of 10.
SCORE_DELTA = 5

SCORE_LABELS = {
    0: "muito fraca",
    1: "fraca",
    2: "razoável",
    3: "forte",
    4: "muito forte",
}

# zxcvbn attack scenarios, in guesses per second.
ATTACK_SCENARIOS = {
    "online_throttling_100_per_hour": 100 / 3600,
    "online_no_throttling_10_per_second": 10,
    "offline_slow_hashing_1e4_per_second": 1e4,
    "offline_fast_hashing_1e10_per_second": 1e10,
}

# nbvcxz-style guess types, in guesses per second. These are the reference
# values used in nbvcxz's TimeEstimateTest; adjust them to your hardware.
GUESS_TYPES = {
    "OFFLINE_MD5": 250_375_000_000,
    "OFFLINE_SHA1": 85_963_750_000,
    "OFFLINE_SHA512": 10_780_875_000,
    "OFFLINE_BCRYPT_5": 130_875,
    "OFFLINE_BCRYPT_10": 4_129,
    "OFFLINE_BCRYPT_12": 1_033,
    "OFFLINE_BCRYPT_14": 259,
    "ONLINE_UNTHROTTLED": 100,
    "ONLINE_THROTTLED": 2,
}


# ---------------------------------------------------------------------------
# Search: most guessable match sequence
# ---------------------------------------------------------------------------

def most_guessable_match_sequence(
    password: str,
    matches: list[Match],
    exclude_additive: bool = False,
    bruteforce_scope: str = "token",
) -> dict:
    """
    Find the non-overlapping sequence of matches with the fewest guesses
    (dynamic programming, O(l_max * (n + m))).

    Gaps that no match covers are filled with bruteforce matches.

    Args:
        password: Password being evaluated.
        matches: Candidate matches (may overlap).
        exclude_additive: Drop the D^(l-1) term.
        bruteforce_scope: "token" computes the character pool of each
            bruteforce segment only; "password" uses the pool of the whole
            password (nbvcxz behaviour, more lenient).

    Returns:
        {"password_length", "guesses", "guesses_log10", "sequence"}
    """
    n = len(password)

    if n == 0:
        return {
            "password_length": 0,
            "guesses": 1,
            "guesses_log10": 0.0,
            "sequence": [],
        }

    password_cardinality = bruteforce_cardinality(password)

    # Partition matches by ending index j, sorted by i for determinism.
    matches_by_j: list[list[Match]] = [[] for _ in range(n)]

    for match in matches:
        matches_by_j[match.j].append(match)

    for group in matches_by_j:
        group.sort(key=lambda m: m.i)

    # optimal_m[k][l]: last match of the best length-l sequence covering the
    #                  prefix up to k (inclusive).
    # optimal_pi[k][l]: product term Prod(m.guesses for m in sequence).
    # optimal_g[k][l]: overall metric.
    optimal_m: list[dict[int, Match]] = [{} for _ in range(n)]
    optimal_pi: list[dict[int, int]] = [{} for _ in range(n)]
    optimal_g: list[dict[int, int]] = [{} for _ in range(n)]

    def update(match: Match, length: int) -> None:
        # Consider a length-`length` sequence ending with `match`.
        k = match.j
        pi = estimate_guesses(match, password)

        if length > 1:
            pi *= optimal_pi[match.i - 1][length - 1]

        g = math.factorial(length) * pi

        if not exclude_additive:
            g += MIN_GUESSES_BEFORE_GROWING_SEQUENCE ** (length - 1)

        # Skip if a sequence with `length` or fewer matches already does better.
        for competing_length, competing_g in optimal_g[k].items():
            if competing_length > length:
                continue

            if competing_g <= g:
                return

        optimal_g[k][length] = g
        optimal_m[k][length] = match
        optimal_pi[k][length] = pi

    def make_bruteforce_match(i: int, j: int) -> Match:
        token = password[i:j + 1]

        cardinality = (
            password_cardinality
            if bruteforce_scope == "password"
            else bruteforce_cardinality(token)
        )

        return Match(
            pattern="bruteforce",
            token=token,
            i=i,
            j=j,
            cardinality=cardinality,
        )

    def bruteforce_update(k: int) -> None:
        # A single bruteforce match spanning the whole k-prefix.
        update(make_bruteforce_match(0, k), 1)

        # Bruteforce matches from (i, k) appended to sequences ending at i-1.
        for i in range(1, k + 1):
            match = make_bruteforce_match(i, k)

            for length, last_match in list(optimal_m[i - 1].items()):
                # Two adjacent bruteforce matches are never optimal: one
                # spanning the same region has the same product, shorter length.
                if last_match.pattern == "bruteforce":
                    continue

                update(match, length + 1)

    for k in range(n):
        for match in matches_by_j[k]:
            if match.i > 0:
                for length in list(optimal_m[match.i - 1]):
                    update(match, length + 1)
            else:
                update(match, 1)

        bruteforce_update(k)

    # Unwind: step backwards from the end to build the final sequence.
    last = n - 1
    best_length = min(optimal_g[last], key=lambda l: optimal_g[last][l])
    guesses = optimal_g[last][best_length]

    sequence: list[Match] = []
    k, length = last, best_length

    while k >= 0:
        match = optimal_m[k][length]
        sequence.insert(0, match)
        k = match.i - 1
        length -= 1

    return {
        "password_length": n,
        "guesses": guesses,
        "guesses_log10": log10(guesses),
        "sequence": sequence,
    }


# ---------------------------------------------------------------------------
# Score
# ---------------------------------------------------------------------------

def guesses_to_score(guesses: int | float) -> int:
    """
    Convert guesses to a 0-4 score (zxcvbn / nbvcxz thresholds).

        0: too guessable           (< 1e3)
        1: very guessable          (< 1e6)   some protection vs throttled online attacks
        2: somewhat guessable      (< 1e8)   some protection vs unthrottled online attacks
        3: safely unguessable      (< 1e10)  some protection vs offline attacks
        4: very unguessable        (>= 1e10) strong protection vs offline attacks
    """
    if guesses < 1e3 + SCORE_DELTA:
        return 0

    if guesses < 1e6 + SCORE_DELTA:
        return 1

    if guesses < 1e8 + SCORE_DELTA:
        return 2

    if guesses < 1e10 + SCORE_DELTA:
        return 3

    return 4


# ---------------------------------------------------------------------------
# Crack time estimates
# ---------------------------------------------------------------------------

_TIME_UNITS = (
    # (limit in seconds, divisor, singular, plural)
    (60, 1, "segundo", "segundos"),
    (3600, 60, "minuto", "minutos"),
    (86400, 3600, "hora", "horas"),
    (86400 * 31, 86400, "dia", "dias"),
    (86400 * 31 * 12, 86400 * 31, "mês", "meses"),
    (86400 * 31 * 12 * 100, 86400 * 31 * 12, "ano", "anos"),
)


def display_time(seconds: float) -> str:
    """Human readable duration (pt-BR), same buckets as zxcvbn."""
    if seconds < 1:
        return "menos de um segundo"

    for limit, divisor, singular, plural in _TIME_UNITS:
        if seconds < limit:
            value = round(seconds / divisor)
            return f"{value} {singular if value == 1 else plural}"

    return "séculos"


def _seconds(guesses: int | float, guesses_per_second: float) -> float:
    # Ints above ~1e308 cannot be converted to float.
    if guesses > 10 ** 300:
        return math.inf

    return guesses / guesses_per_second


def estimate_attack_times(guesses: int | float, scenarios: dict | None = None) -> dict:
    """
    zxcvbn style estimate: seconds and display text for each attack scenario.
    """
    scenarios = scenarios or ATTACK_SCENARIOS

    seconds = {
        name: _seconds(guesses, rate)
        for name, rate in scenarios.items()
    }

    return {
        "crack_times_seconds": seconds,
        "crack_times_display": {
            name: display_time(value)
            for name, value in seconds.items()
        },
    }


def time_to_crack(guesses: int | float, guess_type: str, guess_types: dict | None = None) -> int:
    """
    nbvcxz style estimate: whole seconds (truncated) to exhaust `guesses`
    at the guesses/second configured for `guess_type`.
    """
    guess_types = guess_types or GUESS_TYPES

    return int(guesses) // int(guess_types[guess_type])


__all__ = [
    "ATTACK_SCENARIOS",
    "GUESS_TYPES",
    "SCORE_LABELS",
    "display_time",
    "estimate_attack_times",
    "guesses_to_score",
    "most_guessable_match_sequence",
    "time_to_crack",
]
