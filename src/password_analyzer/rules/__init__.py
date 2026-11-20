from .blacklist import check_blacklist
from .composition import check_composition


RuleMatch = dict


# Check the password against all configured password rules.
def check_password(password: str) -> list[RuleMatch]:
    matches: list[RuleMatch] = []

    blacklist_match = check_blacklist(password)

    if blacklist_match is not None:
        matches.append(blacklist_match)

    matches.extend(check_composition(password))

    return matches


__all__ = [
    "check_password",
]