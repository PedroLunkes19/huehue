KeyboardMatch = dict | None



# Standard QWERTY keyboard layout.

# Layout padrão de um teclado QWERTY
KEYBOARD_ROWS = (
    "1234567890",
    "qwertyuiop",
    "asdfghjkl",
    "zxcvbnm",
)

def find_keyboard_pattern(password: str, min_length: int = 3) -> KeyboardMatch:
    """
        This function finds a consecutive keyboard pattern in a password.

        Supported keyboard rows:
            1234567890
            qwertyuiop
            asdfghjkl
            zxcvbnm

        The search is case-insensitive.

        Examples:
            qwerty123 -> qwerty
            senhaasdf -> asdf
            senha123456 -> 123456
            senhazxcvbn -> zxcvbn
            ytrewq -> ytrewq

        Args:
            password: Password to analyze.
            min_length: Minimum number of consecutive characters to be consider an pattern

        Returns:
            A dictionary containing the detected pattern,
            or None if no keyboard pattern is found.
    """

    """
        Essa função encontra um padrão consecutivo de um teclado em uma senha

        Linhas de teclado suportadas:
            1234567890
            qwertyuiop
            asdfghjkl
            zxcvbnm

        A busca é case-insensitive.

        Exemplos:
            qwerty123 -> qwerty
            senhaasdf -> asdf
            senha123456 -> 123456
            senhazxcvbn -> zxcvbn
            ytrewq -> ytrewq

        Args:
            password: senha para analizar,
            min_length: Número mínimo de caractéres consecutivos para ser considerado um padrão.

        Returns:
            Um dicionário contendo o padrão detectado,
            ou None caso nenhum padrão seja detectado.
    """
    if min_length < 2:
        raise ValueError("min_length must be at least 2")

    normalized_password = password.lower()

    best_match: KeyboardMatch = None

    for row in KEYBOARD_ROWS:
        for direction in (1, -1):
            sequence = row if direction == 1 else row[::-1]

            for start in range(len(sequence)):
                for end in range(start + min_length, len(sequence) + 1):
                    pattern = sequence[start:end]

                    position = normalized_password.find(pattern)

                    if position == -1:
                        continue

                    current_match = {
                        "value": password[position:position + len(pattern)],
                        "length": len(pattern),
                        "start": position,
                        "end": position + len(pattern),
                        "direction": (
                            "forward"
                            if direction == 1
                            else "backward"
                        ),
                        "match_type": "keyboard_pattern",
                    }

                    if best_match is None:
                        best_match = current_match
                        continue

                    # Prefer the longest keyboard pattern.

                    # Prefere o maior padrão de teclado.
                    if current_match["length"] > best_match["length"]:
                        best_match = current_match

    return best_match


__all__ = [
    "find_keyboard_pattern",
]