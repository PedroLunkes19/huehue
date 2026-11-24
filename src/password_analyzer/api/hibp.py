import hashlib
import requests


HIBP_URL = "https://api.pwnedpasswords.com/range/"


# Convert the password into an uppercase SHA-1 hash.

# Converte a senha em um hash maiúsculo de SHA-1
def hash_password(password: str) -> str:
    sha1_hash = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()

    return sha1_hash


# Query the HIBP API with the first five characters of the SHA-1 hash.
# The API returns matching hash suffixes without receiving the full hash.

# Consulta a API do HIBP com os primeiros cinco caractéres do hash SHA-1.
# A API retorna os sufixos dos hashes correspondentes sem nunca ter recebido todo o hash.
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


# Check whether the password hash appears in the HIBP database.

# Checa se o hash da senha aparece ou não no banco de dados do HIBP
def check_password(password: str) -> dict:
    sha1_hash = hash_password(password)

    # Split the hash into a five-character prefix and the remaining suffix.

    # Separa o hash em um prefixo de 5 caractéres e um sufixo do que sobrou.
    prefix = sha1_hash[:5]
    suffix = sha1_hash[5:]

    # Request all hash suffixes associated with the prefix.

    # Requisita todos os hashes com sufixos associados com o prefixo.
    hashes = get_hash_range(prefix)

    # Compare the password hash suffix locally with the API results.

    # Compara o sufixo do hash da senha localmente com os resultados da API.
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