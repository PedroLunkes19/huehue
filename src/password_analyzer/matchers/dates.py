import re


DateMatch = dict | None


DATE_PATTERN = re.compile(
    r"(?<!\d)"
    r"(?P<day>0[1-9]|[12]\d|3[01])"
    r"(?P<separator>/)?"
    r"(?P<month>0[1-9]|1[0-2])"
    r"(?P=separator)?"
    r"(?P<year>\d{2}|\d{4})"
    r"(?!\d)"
)


def find_date(password: str) -> DateMatch:
    """
    Find a date contained in a password.

    Supported formats:
        DD/MM/YY
        DD/MM/YYYY
        DDMMYY
        DDMMYYYY

    Returns:
        A dictionary containing the detected date,
        or None if no date is found.
    """
    match = DATE_PATTERN.search(password)

    if match is None:
        return None

    return {
        "value": match.group(0),
        "day": match.group("day"),
        "month": match.group("month"),
        "year": match.group("year"),
        "start": match.start(),
        "end": match.end(),
        "match_type": "date",
    }


__all__ = [
    "find_date",
]
