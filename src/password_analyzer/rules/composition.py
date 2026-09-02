CompositionMatch = dict | None


# Composition rules for the password
MIN_LENGTH = 8
REQUIRE_UPPERCASE = True
REQUIRE_LOWERCASE = True
REQUIRE_SPECIAL = True


# Check whether the password meets the required composition rules.
def check_composition(password: str) -> CompositionMatch:
    if len(password) < MIN_LENGTH:
        return {
            "match_type": "composition",
            "rule": "min_length",
            "valid": False,
            "value": password,
            "length": len(password),
            "required_length": MIN_LENGTH,
        }

    if REQUIRE_UPPERCASE and not any(character.isupper() for character in password):
        return {
            "match_type": "composition",
            "rule": "uppercase",
            "valid": False,
            "value": password,
        }

    if REQUIRE_LOWERCASE and not any(character.islower() for character in password):
        return {
            "match_type": "composition",
            "rule": "lowercase",
            "valid": False,
            "value": password,
        }

    if REQUIRE_SPECIAL and not any(not character.isalnum() for character in password):
        return {
            "match_type": "composition",
            "rule": "special",
            "valid": False,
            "value": password,
        }

    return None


__all__ = [
    "check_composition",
]