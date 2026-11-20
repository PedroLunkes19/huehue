import argparse
import getpass
import json
import sys

from password_analyzer.core.analyzer import PasswordAnalyzer


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="password-analyzer",
        description="Avalia a força de uma senha (nota de 0 a 4).",
    )

    parser.add_argument(
        "password",
        nargs="?",
        help="Senha a avaliar. Se omitida, será solicitada sem eco "
             "(evita deixar a senha no histórico do shell).",
    )
    parser.add_argument(
        "--no-hibp",
        action="store_true",
        help="Não consulta a API Have I Been Pwned (análise 100%% local).",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Imprime o resultado completo em JSON.",
    )

    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    password = args.password
    if password is None:
        password = input("Senha: ")

    analyzer = PasswordAnalyzer()
    result = analyzer.analyze(password, check_breach=not args.no_hibp)

    if args.json:
        print(json.dumps(result.to_dict(), ensure_ascii=False, indent=2, default=str))
        return 0

    print(f"Nota: {result.score}/4 ({result.label})")
    print(f"Tentativas estimadas: ~10^{result.guesses_log10:.1f} "
          f"({result.entropy_bits:.1f} bits)")

    if result.breached is None and not args.no_hibp:
        print("Vazamentos: não foi possível consultar o HIBP")
    elif result.breached is not None:
        print("Vazamentos: "
              + (f"encontrada {result.breach_count}x" if result.breached else "não encontrada"))

    print("\nTempo para quebrar:")
    for scenario, text in result.crack_times_display.items():
        print(f"  {scenario}: {text}")

    if result.warnings:
        print("\nAvisos:")
        for warning in result.warnings:
            print(f"  - {warning}")

    if result.suggestions:
        print("\nSugestões:")
        for suggestion in result.suggestions:
            print(f"  - {suggestion}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
