BlacklistMatch = dict | None


# Dictionary of blacklisted passwords
# Dicionário das senhas proibidas
BLACKLIST = {
    # Add your passwords here, follow the example
    # Adicione suas senhas aqui, segue o exemplo
    "12345",
    "admin",
    "password",
}


# Check whether the password is present in the blacklist.
# Checa se a senha é ou não uma senha proibida
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