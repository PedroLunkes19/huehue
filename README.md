# huehue - Password Strength Estimator

huehue is a *python-based* password strength estimator heavily inspired by the work in [zxcvbn](https://github.com/dropbox/zxcvbn) (Dropbox) and [nbvcxz](https://github.com/GoSimpleLLC/nbvcxz) (GoSimple).

huehue estimates the number of guesses needed to crack a password. To do so, it identifies patterns in the password (dictionary words, names, dates, sequences, keyboard rows and repetitions), calculates the number of guesses for each pattern and converts the total into a score from 0 to 4. The result also includes the estimated crack time, warnings and suggestions.

## What the tool does

- **Checks for breaches** on [Have I Been Pwned](https://haveibeenpwned.com/Passwords) using k-anonymity: the password is not sent, only the first 5 characters of its SHA-1 hash.
- **Detects patterns**: common passwords, first names and surnames (Brazil and US), English words, dates (`DDMMYY`, `DD/MM/YYYY`...), sequences (`123`, `987`), keyboard rows (`qwerty`, `asdf`) and repeated characters (`aaaa`).
- **Estimates the number of guesses** by selecting, through dynamic programming, the decomposition of the password with the lowest number of guesses (as in zxcvbn).
- **Calculates a score from 0 to 4** and the crack time in four attack scenarios (online with throttling, online without throttling, offline with slow hashing and offline with fast hashing).
- **Generates warnings and suggestions** based on the patterns found and the rules violated.
- **Runs offline**: with `--no-hibp` the whole analysis is local.

> The analysis messages (warnings, suggestions, labels and crack time text) are currently in PT-BR.

## How it works (overview)

```
password
  │
  ├─► HIBP (k-anonymity) ─────────────┐
  ├─► rules (blacklist, composition) ─┤
  │                                   │
  ├─► matchers (dictionary, date,     │
  │    repetition, sequence, keyboard)│
  │         │                         │
  │         ▼                         │
  │   guess estimate per pattern      │
  │   (core/entropy.py)               │
  │         │                         │
  │         ▼                         │
  │   best decomposition of the       │
  │   password (core/scoring.py)      │
  │         │                         │
  │         ▼                         ▼
  └────► raw score (0-4) ──► final score
```

Final score rule:

| Situation | Final score |
|---|---|
| Password found in a breach or in the blacklist | **0** (very weak) |
| Any other password | **1 to 4**, from the estimated number of guesses |

| Estimated guesses | Raw score | Label |
|---|---|---|
| < 10³ | 0 (becomes 1 if there is no breach) | weak |
| < 10⁶ | 1 | weak |
| < 10⁸ | 2 | fair |
| < 10¹⁰ | 3 | strong |
| ≥ 10¹⁰ | 4 | very strong |

The thresholds use an offset of 5 (`SCORE_DELTA`), as explained in the [evaluation methodology](docs/EN/methodology.md#61-score).

## Installation

Requires **Python 3.10 or higher**.

```bash
git clone <repository-url> huehue
cd huehue

# optional, but recommended
python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate

pip install -e .
```

The only runtime dependency is `requests` (used for the HIBP query), which is installed automatically.

## Usage

### Command line

Two equivalent commands are installed: `huehue` and `password-analyzer`.

```bash
# Password as an argument (note: it is stored in the shell history)
huehue pedro123

# No argument: the password is requested at the prompt
huehue

# 100% local analysis, without querying HIBP
huehue --no-hibp pedro123

# Full result as JSON
huehue --json pedro123
```

Example output (`huehue --no-hibp pedro123`):

```
Nota: 1/4 (fraca)
Tentativas estimadas: ~10^4.2 (13.9 bits)

Tempo para quebrar:
  online_throttling_100_per_hour: 6 dias
  online_no_throttling_10_per_second: 25 minutos
  offline_slow_hashing_1e4_per_second: 2 segundos
  offline_fast_hashing_1e10_per_second: menos de um segundo

Avisos:
  - A senha não contém letras maiúsculas.
  - A senha não contém caracteres especiais.
  - Nomes próprios são fáceis de adivinhar.
  - Sequências como '123' são fáceis de adivinhar.

Sugestões:
  - Use uma senha mais longa (passphrases funcionam bem).
  - Evite palavras, nomes, datas e sequências previsíveis; combine palavras não relacionadas.
```

> If HIBP cannot be queried (for example, without an internet connection), the local analysis continues and the breach field is reported as "could not query".

### As a Python library

```python
from password_analyzer.core.analyzer import PasswordAnalyzer

# breach_checker=None -> fully local analysis (no network)
analyzer = PasswordAnalyzer(breach_checker=None)

result = analyzer.analyze("pedro123")
print(result.score, result.label)        # 1 fraca
print(result.guesses_log10)              # ~4.2
print(result.warnings)
```

Create **a single instance** and reuse it: the dictionaries (some with millions of lines) are loaded once, in the constructor. There is also the shortcut `analyze_password(password)` in `core/analyzer.py`, which creates and reuses a default instance. See [`examples/example.py`](examples/example.py).

The `PasswordResult` object contains, among others: `score`, `raw_score`, `label`, `guesses`, `guesses_log10`, `entropy_bits`, `breached`, `breach_count`, `blacklisted`, `rule_violations`, `sequence` (the patterns found), `crack_times_seconds`, `crack_times_display`, `warnings` and `suggestions`.

The analyzer does not store the complete password in a dedicated field. However, the analysis result may contain sensitive password data: `Match` objects retain matched tokens, and rule violations may include values derived from the original password. These fields are also included when the result is serialized with `to_dict()` or exported as JSON. Therefore, analysis results and JSON outputs should be treated as sensitive data.

## Tests

```bash
pip install pytest
python -m pytest
```

The tests are in `tests/` and can also be run with `python -m unittest discover -s tests -t .`. The tests in `tests/test_hibp.py` query the real HIBP API and require internet access; all the others run offline.

## Project structure

```
huehue/
├── src/password_analyzer/
│   ├── main.py          # CLI
│   ├── api/             # HIBP integration
│   ├── core/            # orchestration, guess estimation and scoring
│   ├── matchers/        # pattern detectors and dictionary loading
│   ├── rules/           # blacklist and composition rules
│   ├── models/          # Match and PasswordResult
│   └── data/            # dictionaries (common passwords, names, words...)
├── tests/
├── examples/
└── docs/
```

## Where to find more information

The project documentation is available in English and Brazilian Portuguese (PT-BR).

| Document | English | Português (PT-BR) |
|---|---|---|
| Architecture | [`architecture.md`](docs/EN/architecture.md) | [`arquitetura.md`](docs/PT-BR/arquitetura.md) |
| Methodology | [`methodology.md`](docs/EN/methodology.md) | [`metodologia.md`](docs/PT-BR/metodologia.md) |
| HIBP Integration | [`hibp_EN.md`](docs/EN/hibp_EN.md) | [`hibp_PTBR.md`](docs/PT-BR/hibp_PTBR.md) |



## Known limitations

huehue is inspired by zxcvbn and nbvcxz but does not fully reimplement either evaluator. Its pattern detection has some limitations: it does not recognize letter substitutions (e.g., `p4ssw0rd`), reversed words, approximate word matches, letter sequences, or repeated blocks. Its keyboard detector only recognizes straight-line sequences across four QWERTY keyboard rows, and its date detector supports only `DDMMYY` and `DDMMYYYY` formats, with or without `/` separators. Additionally, only the first occurrence of date, repetition, sequence, and keyboard patterns is detected, and password pattern analysis is limited to the first 128 characters. The dictionaries include Brazilian and English names and surnames, but common words are limited to English. For a detailed comparison with zxcvbn and nbvcxz, as well as the complete list of known limitations, see [the evaluation methodology](docs/EN/methodology.md#7-differences-between-the-evaluators-and-huehues-limitations).

The score is an estimate and depends on the dictionaries and patterns described in [`docs/EN/methodology.md`](docs/EN/methodology.md).

## References

- **zxcvbn** — <https://github.com/dropbox/zxcvbn>. Paper: Daniel Lowe Wheeler, *zxcvbn: Low-Budget Password Strength Estimation*, USENIX Security 2016.
- **nbvcxz** — <https://github.com/GoSimpleLLC/nbvcxz>
- **Have I Been Pwned: Pwned Passwords** — <https://haveibeenpwned.com/API/v3#PwnedPasswords>

## License

GNU GPL v3. See the [`LICENSE`](LICENSE) file.
