BlacklistMatch = dict | None


# Dictionary of blacklisted passwords
BLACKLIST = {
    # Add your passwords here, follow the example:
    "12345",
    "admin",
    "password",
}


# Check whether the password is present in the blacklist.
def check_blacklist(password: str) -> BlacklistMatch:
    if password not in BLACKLIST:
        return None

    return {
        "value": password,
        "match_type": "blacklist",
        "valid": False,
    }


__all__ = [
    "check_blacklist",
]