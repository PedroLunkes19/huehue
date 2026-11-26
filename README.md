# huehue - Password Strength Estimator

huehue is a *python-based* password strength estimator heavily inspired by the word in [zxcvbn](https://github.com/dropbox/zxcvbn) (Dropbox) and [nbvcxz](https://github.com/GoSimpleLLC/nbvcxz) (GoSimple).

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

The `PasswordResult` object contains, among others: `score`, `raw_score`, `label`, `guesses`, `guesses_log10`, `entropy_bits`, `breached`, `breach_count`, `blacklisted`, `rule_violations`, `sequence` (the patterns found), `crack_times_seconds`, `crack_times_display`, `warnings` and `suggestions`. The password itself is **never** stored in the result.

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

The documents in `docs/` are written in Portuguese.

| Document | Contents |
|---|---|
| [`docs/architecture.md`](docs/architecture.md) | Architecture, the responsibility of each folder and file, and the step-by-step code flow |
| [`docs/methodology.md`](docs/methodology.md) | The mathematics and methodology of the evaluation, with references to zxcvbn and nbvcxz and where to check them in their repositories |
| [`docs/hibp.md`](docs/hibp.md) | How the Have I Been Pwned integration works |

## Known limitations

huehue implements part of the ideas of zxcvbn and nbvcxz and is **not a faithful reimplementation of either**. It does not perform "leet" substitution (`p4ssw0rd`), does not recognize reversed words and does not do approximate matching (Levenshtein distance), and the keyboard detector only recognizes straight-line sequences. The full list of differences is in [`docs/methodology.md`](docs/methodology.md#9-diferenças-em-relação-ao-zxcvbn-e-ao-nbvcxz).

The score is an estimate and depends on the dictionaries and patterns described in [`docs/methodology.md`](docs/methodology.md).

## References

- **zxcvbn** — <https://github.com/dropbox/zxcvbn>. Paper: Daniel Lowe Wheeler, *zxcvbn: Low-Budget Password Strength Estimation*, USENIX Security 2016.
- **nbvcxz** — <https://github.com/GoSimpleLLC/nbvcxz>
- **Have I Been Pwned: Pwned Passwords** — <https://haveibeenpwned.com/API/v3#PwnedPasswords>

## License

GNU GPL v3. See the [`LICENSE`](LICENSE) file.
