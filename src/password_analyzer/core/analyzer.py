"""
Password analysis workflow (see docs/architecture.md):

    HIBP check -> rules -> pattern matchers -> guess search -> score

Final score:
    0/4  password found in a breach (or blacklisted)
    1-4  otherwise, from the estimated number of guesses
         (the raw 0-4 zxcvbn score is kept in `raw_score`)
"""

from operator import add

import requests

from ..api.hibp import check_password as hibp_check_password
from ..matchers import (
    find_date,
    find_keyboard_pattern,
    find_patterns,
    find_repetition,
    load_datasets,
)
from ..matchers.dictionary import NORMALIZED_CASE_DATASETS, find_best_match
from ..models.result import Match, PasswordResult
from ..rules import check_password as check_rules
from .entropy import (
    bruteforce_cardinality,
    bruteforce_guesses,
    build_rank_tables,
    guesses_to_entropy_bits,
)
from .scoring import (
    SCORE_LABELS,
    estimate_attack_times,
    guesses_to_score,
    most_guessable_match_sequence,
)


# Passwords longer than this are analyzed only up to this many characters,
# bounding the cost of the search. (The breach check uses the full password.)
MAX_ANALYZED_LENGTH = 128

MIN_DICTIONARY_LENGTH = 3

_DICTIONARY_WARNINGS = {
    "common_passwords": "Esta senha possui partes/está entre as senhas comuns.",
    "names_brazil": "Nomes próprios são fáceis de adivinhar.",
    "names_english": "Nomes próprios são fáceis de adivinhar.",
    "surnames_brazil": "Sobrenomes são fáceis de adivinhar.",
    "surnames_english": "Sobrenomes são fáceis de adivinhar.",
    "eff_large": "Palavras de dicionário são fáceis de adivinhar.",
    "english": "Palavras de dicionário são fáceis de adivinhar.",
}

_RULE_WARNINGS = {
    "min_length": "A senha é curta demais (mínimo de {required_length} caracteres).",
    "uppercase": "A senha não contém letras maiúsculas.",
    "lowercase": "A senha não contém letras minúsculas.",
    "special": "A senha não contém caracteres especiais.",
    "number": "A senha não contém números.",
}


class PasswordAnalyzer:
    """
    Evaluates passwords. Datasets and rank tables are loaded once, so reuse
    a single instance to analyze many passwords.

    Args:
        datasets: Loaded dictionary datasets (default: load_datasets()).
        breach_checker: Callable(password) -> {"found": bool, "count": int}.
            Defaults to the HIBP k-anonymity API. Pass None to disable.
        max_length: Maximum number of characters analyzed locally.
        bruteforce_scope: "token" (default, conservative) or "password"
            (nbvcxz behaviour). See scoring.most_guessable_match_sequence.
    """

    def __init__(
        self,
        datasets: dict | None = None,
        breach_checker=hibp_check_password,
        max_length: int = MAX_ANALYZED_LENGTH,
        bruteforce_scope: str = "token",
    ):
        self.datasets = datasets if datasets is not None else load_datasets()
        self.rank_tables = build_rank_tables(self.datasets)
        self.breach_checker = breach_checker
        self.max_length = max_length
        self.bruteforce_scope = bruteforce_scope

    # ------------------------------------------------------------------
    # Matcher output -> Match objects
    # ------------------------------------------------------------------

    def build_matches(self, password: str) -> list[Match]:
        """Run every matcher and convert their results into Match objects."""
        matches: list[Match] = []

        # Dictionary.
        for name, dataset in self.datasets.items():
            self._collect_dictionary_matches(password, 0, name, dataset, matches)

        # Date.
        item = find_date(password)
        if item is not None:
            matches.append(Match(
                pattern="date",
                token=item["value"],
                i=item["start"],
                j=item["end"] - 1,
                year=self._expand_year(item["year"]),
                separator=len(item["value"]) > (
                    len(item["day"]) + len(item["month"]) + len(item["year"])
                ),
            ))

        # Repetition of a single character (e.g. "aaaa").
        item = find_repetition(password, min_length=3)
        if item is not None:
            character = Match(
                pattern="bruteforce",
                token=item["character"],
                i=0,
                j=0,
                cardinality=bruteforce_cardinality(item["character"]),
            )

            matches.append(Match(
                pattern="repeat",
                token=item["value"],
                i=item["start"],
                j=item["end"] - 1,
                base_guesses=bruteforce_guesses(character),
                repeat_count=item["length"],
            ))

        # Numeric sequences (123, 321, ...) and other general patterns.
        for item in find_patterns(password):
            if item["match_type"] != "numeric_sequence":
                # "first character uppercase" and "trailing numbers/special"
                # are handled by the uppercase variations and by the
                # bruteforce estimate; they are not standalone matches.
                continue

            value = item["value"]
            matches.append(Match(
                pattern="sequence",
                token=value,
                i=item["start"],
                j=item["end"] - 1,
                ascending=value[1] > value[0],
            ))

        # Keyboard rows (qwerty, asdf, 1234567890, ...), straight runs only.
        item = find_keyboard_pattern(password, min_length=3)
        if item is not None:
            token = item["value"]
            matches.append(Match(
                pattern="spatial",
                token=token,
                i=item["start"],
                j=item["end"] - 1,
                turns=1,
                shifted_count=sum(1 for c in token if c.isupper()),
            ))

        return matches

    def _collect_dictionary_matches(
        self,
        text: str,
        offset: int,
        name: str,
        dataset: dict,
        out: list[Match],
    ) -> None:
        """
        find_best_match returns a single match per dataset. To give the
        search every candidate it needs (e.g. "help" + "here"), the text
        on both sides of each match is searched again, recursively.
        """
        if len(text) < MIN_DICTIONARY_LENGTH:
            return

        normalize = name in NORMALIZED_CASE_DATASETS
        found = find_best_match(
            password=text,
            entries=dataset["entries"],
            frequencies=dataset["frequencies"],
            min_length=MIN_DICTIONARY_LENGTH,
            normalize_case=normalize,
        )

        if found is None:
            return

        table = self.rank_tables[name]
        key = found["value"].casefold() if normalize else found["value"]
        rank = table["ranks"].get(key) if table["ordered"] else None

        if rank is None:
            rank = table["size"]

        start = offset + found["start"]
        end = offset + found["end"]

        out.append(Match(
            pattern="dictionary",
            token=found["value"],
            i=start,
            j=end - 1,
            dataset=name,
            rank=rank,
        ))

        self._collect_dictionary_matches(
            text[:found["start"]], offset, name, dataset, out
        )
        self._collect_dictionary_matches(
            text[found["end"]:], end, name, dataset, out
        )

    @staticmethod
    def _expand_year(year: str) -> int:
        value = int(year)

        if len(year) == 4:
            return value

        # Two digit years: 00-49 -> 2000s, 50-99 -> 1900s.
        return 2000 + value if value < 50 else 1900 + value

    # ------------------------------------------------------------------
    # Breach check
    # ------------------------------------------------------------------

    def _check_breach(self, password: str) -> tuple[bool | None, int]:
        if self.breach_checker is None:
            return None, 0

        try:
            result = self.breach_checker(password)
        except (requests.RequestException, ValueError):
            # Network failure or malformed answer: continue with the local
            # analysis and report the breach status as unknown.
            return None, 0

        return result["found"], result["count"]

    # ------------------------------------------------------------------
    # Feedback
    # ------------------------------------------------------------------

    @staticmethod
    def _feedback(sequence: list[Match], violations: list[dict], length: int):
        warnings: list[str] = []

        def add(message: str) -> None:
            if message not in warnings:
                warnings.append(message)

        for violation in violations:
            if violation["match_type"] == "blacklist":
                add("Esta senha está na lista de senhas proibidas.")
            else:
                template = _RULE_WARNINGS.get(violation["rule"])
                template = _RULE_WARNINGS.get(violation["rule"], "A senha não atende à regra: {rule}.")
                add(template.format(**violation))

        for match in sequence:
            if match.pattern == "dictionary":
                add(_DICTIONARY_WARNINGS.get(match.dataset, "Palavra previsível."))
            elif match.pattern == "spatial":
                add("Sequências de teclado como 'qwerty' são fáceis de adivinhar.")
            elif match.pattern == "repeat":
                add("Caracteres repetidos como 'aaa' são fáceis de adivinhar.")
            elif match.pattern == "sequence":
                add("Sequências como '123' são fáceis de adivinhar.")
            elif match.pattern == "date":
                add("Datas são fáceis de adivinhar.")

        suggestions: list[str] = []

        if length < 12:
            suggestions.append("Use uma senha mais longa (passphrases funcionam bem).")

        if any(m.pattern != "bruteforce" for m in sequence):
            suggestions.append(
                "Evite palavras, nomes, datas e sequências previsíveis; "
                "combine palavras não relacionadas."
            )

        return warnings, suggestions

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def analyze(self, password: str, check_breach: bool = True) -> PasswordResult:
        """Evaluate `password` and return a PasswordResult."""
        breached, breach_count = (
            self._check_breach(password) if check_breach else (None, 0)
        )

        violations = check_rules(password)
        blacklisted = any(v["match_type"] == "blacklist" for v in violations)

        analyzed = password[:self.max_length]
        matches = self.build_matches(analyzed)

        search = most_guessable_match_sequence(
            analyzed,
            matches,
            bruteforce_scope=self.bruteforce_scope,
        )

        guesses = search["guesses"]
        raw_score = guesses_to_score(guesses)

        if breached or blacklisted:
            score = 0
        else:
            # Methodology: passwords not found in breaches score 1-4.
            score = max(raw_score, 1)

        warnings, suggestions = self._feedback(
            search["sequence"], violations, len(password)
        )

        if breached:
            warnings.insert(
                0,
                f"Esta senha apareceu em vazamentos de dados {breach_count} vezes.",
            )

        times = estimate_attack_times(guesses)

        return PasswordResult(
            password_length=len(password),
            score=score,
            raw_score=raw_score,
            label=SCORE_LABELS[score],
            guesses=guesses,
            guesses_log10=search["guesses_log10"],
            entropy_bits=guesses_to_entropy_bits(guesses),
            breached=breached,
            breach_count=breach_count,
            blacklisted=blacklisted,
            rule_violations=violations,
            sequence=search["sequence"],
            crack_times_seconds=times["crack_times_seconds"],
            crack_times_display=times["crack_times_display"],
            warnings=warnings,
            suggestions=suggestions,
        )


_default_analyzer: PasswordAnalyzer | None = None


def analyze_password(password: str, check_breach: bool = True) -> PasswordResult:
    """Convenience wrapper around a lazily created default PasswordAnalyzer."""
    global _default_analyzer

    if _default_analyzer is None:
        _default_analyzer = PasswordAnalyzer()

    return _default_analyzer.analyze(password, check_breach=check_breach)


__all__ = [
    "PasswordAnalyzer",
    "analyze_password",
]
