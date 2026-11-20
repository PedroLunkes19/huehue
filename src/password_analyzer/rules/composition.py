CompositionMatch = dict


# Composition rules for the password
MIN_LENGTH = 8
REQUIRE_UPPERCASE = True
REQUIRE_LOWERCASE = True
REQUIRE_SPECIAL = True
REQUIRE_NUMBER = True


# Check the password against ALL composition rules.
# Returns one entry per violated rule (empty list when the password is valid).
def check_composition(password: str) -> list[CompositionMatch]:
    violations: list[CompositionMatch] = []

    if len(password) < MIN_LENGTH:
        violations.append({
            "match_type": "composition",
            "rule": "min_length",
            "valid": False,
            "value": password,
            "length": len(password),
            "required_length": MIN_LENGTH,
        })

    if REQUIRE_UPPERCASE and not any(character.isupper() for character in password):
        violations.append({
            "match_type": "composition",
            "rule": "uppercase",
            "valid": False,
            "value": password,
        })

    if REQUIRE_LOWERCASE and not any(character.islower() for character in password):
        violations.append({
            "match_type": "composition",
            "rule": "lowercase",
            "valid": False,
            "value": password,
        })

    if REQUIRE_SPECIAL and not any(not character.isalnum() for character in password):
        violations.append({
            "match_type": "composition",
            "rule": "special",
            "valid": False,
            "value": password,
        })

    if REQUIRE_NUMBER and not any(character.isdigit() for character in password):
        violations.append({
            "match_type": "composition",
            "rule": "number",
            "valid": False,
            "value": password,
        })

    return violations


__all__ = [
    "check_composition",
]