import hashlib
import requests


HIBP_URL = "https://api.pwnedpasswords.com/range/"


def hash_password(password: str) -> str:

    sha1_hash = hashlib.sha1(
        password.encode("utf-8")
    ).hexdigest().upper()

    return sha1_hash


def get_hash_range(prefix: str) -> str:

    response = requests.get(
        HIBP_URL + prefix,
        headers={
            "User-Agent": "PasswordAnalyzer"
        },
        timeout=10
    )

    response.raise_for_status()

    return response.text


def check_password(password: str) -> dict:

    sha1_hash = hash_password(password)

    prefix = sha1_hash[:5]
    suffix = sha1_hash[5:]

    hashes = get_hash_range(prefix)

    for line in hashes.splitlines():

        hash_suffix, count = line.split(":")

        if hash_suffix == suffix:

            return {
                "found": True,
                "count": int(count)
            }

    return {
        "found": False,
        "count": 0
    }