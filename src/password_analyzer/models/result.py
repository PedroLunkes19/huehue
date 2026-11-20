from __future__ import annotations

from dataclasses import dataclass, field, asdict


@dataclass
class Match:
    """
    A pattern found in a password, expressed as a span [i, j] (inclusive).

    This is the unified structure consumed by the scoring search.
    The matchers return heterogeneous dictionaries; the analyzer converts
    them into Match objects (see core/analyzer.py).

    Patterns: dictionary | date | repeat | sequence | spatial | bruteforce
    """

    pattern: str
    token: str
    i: int
    j: int

    # Filled by core.entropy.estimate_guesses (cached after the first call).
    guesses: int | None = None
    guesses_log10: float | None = None

    # dictionary
    dataset: str | None = None
    rank: int | None = None
    uppercase_variations: int = 1

    # repeat
    base_guesses: int | None = None
    repeat_count: int = 0

    # sequence
    ascending: bool = True

    # spatial (keyboard)
    turns: int = 1
    shifted_count: int = 0

    # date
    year: int | None = None
    separator: bool = False

    # bruteforce
    cardinality: int | None = None


@dataclass
class PasswordResult:
    """Final evaluation of a password. The password itself is never stored."""

    password_length: int

    # Final score (0-4) and the raw guess-based score before any override.
    score: int
    raw_score: int
    label: str

    # Search space estimate.
    guesses: int
    guesses_log10: float
    entropy_bits: float

    # Breach information. breached is None when the check was not performed
    # or could not be completed (e.g. no network).
    breached: bool | None = None
    breach_count: int = 0

    blacklisted: bool = False
    rule_violations: list[dict] = field(default_factory=list)

    sequence: list[Match] = field(default_factory=list)

    crack_times_seconds: dict[str, float] = field(default_factory=dict)
    crack_times_display: dict[str, str] = field(default_factory=dict)

    warnings: list[str] = field(default_factory=list)
    suggestions: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)


__all__ = ["Match", "PasswordResult"]
