# Architecture

## 1. Overview

`huehue` is organized into modules with distinct responsibilities. The `core` package coordinates password analysis, `matchers` identify predictable patterns, `rules` apply independent checks, and `models` define the data structures used to represent analysis results.

## 2. Project Structure

The relevant project structure is organized as follows:

```text
huehue/
├── src/
│   └── password_analyzer/
│       ├── api/
│       │   └── hibp.py
│       ├── core/
│       │   ├── analyzer.py
│       │   ├── entropy.py
│       │   └── scoring.py
│       ├── matchers/
│       │   ├── dates.py
│       │   ├── dictionary.py
│       │   ├── keyboard.py
│       │   ├── patterns.py
│       │   └── repetition.py
│       ├── rules/
│       │   ├── blacklist.py
│       │   └── composition.py
│       ├── models/
│       │   └── result.py
│       ├── data/
│       └── main.py
├── tests/
├── examples/
├── docs/
├── pyproject.toml
└── requirements.txt
```

## 3. Module Responsibilities

### `api/`

Provides communication with external services. The current implementation integrates with the Have I Been Pwned (HIBP) Pwned Passwords API to check whether a password has appeared in known data breaches.

### `core/`

Contains the main password-analysis workflow and the calculations used to evaluate password strength.

- **`analyzer.py`** coordinates the analysis. It performs the breach check, applies password rules, invokes the matchers, builds the candidate matches, calls the scoring search, and assembles the `PasswordResult` object. It also generates warnings and suggestions.
- **`entropy.py`** estimates the number of guesses associated with each match type, calculates brute-force character-set cardinality, builds dictionary-rank tables, and converts guess estimates into entropy bits.
- **`scoring.py`** searches for the most guessable non-overlapping sequence of matches using dynamic programming. It also converts the resulting guess estimate into a score and estimates attack times under predefined scenarios.

`scoring.py` and `entropy.py` work together: the scoring search calls `estimate_guesses()` from `entropy.py` to obtain the cost of each candidate match. The former is responsible for selecting the decomposition and calculating the overall score; the latter is responsible for estimating the cost of individual patterns.

### `matchers/`

Contains the functions that identify predictable structures in a password.

- **`dictionary.py`** searches for words, common passwords, names, and surnames in the loaded datasets. Comparisons are case-insensitive only for the datasets configured for case normalization.
- **`dates.py`** searches for date-like sequences in the formats described by the matcher. It returns the first occurrence found.
- **`repetition.py`** detects consecutive repetitions of the same character and returns the first occurrence found.
- **`patterns.py`** detects numeric sequences in ascending or descending order. The analyzer uses the first numeric sequence returned by this matcher. Other patterns produced by this module, such as a single initial uppercase letter or trailing numbers/special characters, are not added as independent matches by the analyzer.
- **`keyboard.py`** detects straight sequences in the supported horizontal QWERTY rows, in either direction. When more than one candidate is found, it keeps the longest one. Diagonal keyboard paths are not covered.

The analyzer converts the matcher outputs into `Match` objects, which provide a common structure for the scoring search.

### `rules/`

Contains checks that are applied independently of the pattern matchers.

- **`composition.py`** checks the minimum length and the presence of uppercase letters, lowercase letters, numbers, and special characters. Violations generate warnings, but composition violations alone do not force the final score to zero.
- **`blacklist.py`** checks whether the complete password is present in the built-in blacklist. The current source contains the example entries `12345`, `admin`, and `password`. A blacklist match forces the final score to zero.

The blacklist is defined in the source code; it is not currently exposed as a runtime configuration option.

### `models/`

Defines the data structures used during analysis and to represent the final result.

- **`Match`** represents a detected pattern, including its type, position, token, and pattern-specific metadata. Its `guesses` fields cache the estimate calculated by `entropy.py`.
- **`PasswordResult`** stores the final score, raw score, guess and entropy estimates, breach information, rule violations, selected match sequence, attack-time estimates, warnings, and suggestions. Its `to_dict()` method converts the result to a dictionary for JSON serialization.

Although `PasswordResult` has no dedicated field containing the complete password, its current `sequence` field can retain `Match` objects whose `token` values contain portions of the password. The `rule_violations` field can also contain original values. Since `to_dict()` serializes the dataclass fields, these values may be included in JSON output. This is a known information-exposure risk; the statement that the result never stores password data should therefore not be interpreted as meaning that the result is free of sensitive password fragments.

### `data/`

Contains the datasets used by the dictionary matcher. The current collection includes common passwords, English words, Brazilian and English first names, and Brazilian and English surnames. The datasets are loaded when a `PasswordAnalyzer` instance is initialized and are used to build the corresponding rank tables.

### `main.py`

Provides the command-line interface. It accepts an optional password argument and supports options to disable the HIBP check (`--no-hibp`) or print the complete result as JSON (`--json`). The current interactive input path uses `input()`, so typed characters are displayed in the terminal. Supplying a password as a command-line argument can also expose it through shell history or process listings, depending on the environment.

### `tests/` and `examples/`

`tests/` contains automated tests for the application. `examples/` contains example scripts demonstrating its use.

## 4. Analysis Workflow

The `PasswordAnalyzer.analyze()` method coordinates the following stages:

1. **Breach check:** when enabled, the complete password is hashed locally and checked through the HIBP range API. If the check is disabled or cannot be completed, the breach status is recorded as unknown (`None`) and local analysis continues.
2. **Password rules:** the blacklist and composition rules are evaluated against the complete password. A blacklist match is recorded separately from composition violations.
3. **Local analysis input:** pattern analysis is limited to the first 128 characters by default. This limit can be changed through the `max_length` constructor argument.
4. **Pattern detection:** the matchers search the analyzed portion of the password. Their results are converted into `Match` objects.
5. **Sequence search:** `scoring.py` evaluates candidate matches and requests their individual estimates from `entropy.py`. Unmatched portions are represented by brute-force matches.
6. **Result assembly:** the analyzer combines the score, breach status, rule violations, selected matches, attack-time estimates, warnings, and suggestions in a `PasswordResult`.

A failed or unavailable HIBP request does not stop the analysis: the application continues with local checks and records the breach status as unknown. A password found in HIBP or in the blacklist receives a final score of `0/4`. Otherwise, the final score is based on the guess-based score, with a minimum value of `1/4`. The mathematical criteria behind the guess estimates and score are described in `methodology.md`.

```text
                         Password input
                               |
                               v
                  HIBP breach check (if enabled)
                               |
                               v
                    Password rules
                 (blacklist and composition)
                               |
                               v
                       Local analysis
                    (up to 128 chars by
                         default)
                               |
                  +------------+------------+
                  |            |            |
                  v            v            v
              Dictionary    Pattern     Other pattern
               matching    detection      matchers
                  |            |            |
                  +------------+------------+
                               |
                               v
                         Match objects
                               |
                               v
                  Sequence search (scoring.py)
                               |
                               | requests estimates
                               v
                   Guess estimation (entropy.py)
                               |
                               | returns estimates
                               v
                  Sequence search continues
                               |
                               v
                     Sequence selection
                               |
                               v
                  Guess estimate and raw score
                               |
                  +------------+------------+
                  |                         |
                  v                         v
       Breached or blacklisted?        No override
                  |                         |
             Yes  |                         | No
                  v                         v
              Score 0/4              Final score 1-4/4
                  |                         |
                  +------------+------------+
                               |
                               v
                  Attack times and feedback
                               |
                               v
                         PasswordResult
```

## 5. Architectural Decisions

### Separation of Responsibilities

Pattern detection, match-cost estimation, sequence selection, password rules, and result representation are handled by separate modules. This keeps each component focused on a specific responsibility and makes the analysis workflow easier to inspect.

### Common Match Representation

The matcher functions return different kinds of data. The analyzer converts those outputs into `Match` objects before passing them to the sequence search. This provides a consistent representation regardless of which matcher identified a pattern.

### Dataset-driven Dictionary Matching

Dictionary entries are kept in external data files rather than embedded in matcher logic. The analyzer loads the datasets and builds the rank tables when a `PasswordAnalyzer` instance is initialized. Custom datasets can also be supplied through the public constructor.

### Configurable Breach-check Dependency

The `PasswordAnalyzer` accepts a `breach_checker` callable. This allows the default HIBP integration to be used, replaced by another compatible callable, or disabled by passing `None`. If a breach check cannot be completed, local analysis can still proceed.

### Separation of Rules and Scoring

Composition checks and blacklist checks are implemented separately from pattern matching and guess estimation. Composition violations generate feedback, while a blacklist match can override the final score. The detailed evaluation criteria are documented in `methodology.md`.

## 6. Configuration and Public Interface

The `PasswordAnalyzer` constructor exposes the following parameters:

- `datasets`: custom dictionary datasets. When omitted, the built-in datasets are loaded.
- `breach_checker`: callable used for the breach check. It defaults to the HIBP checker; passing `None` disables it.
- `max_length`: maximum number of characters analyzed by the local pattern search. The default is 128.
- `bruteforce_scope`: determines whether brute-force character cardinality is calculated per unmatched segment (`"token"`, the default) or from the complete password (`"password"`).

The main public method is `analyze(password, check_breach=True)`, which returns a `PasswordResult`. The module also provides the `analyze_password()` convenience function, which reuses a lazily initialized default analyzer.

The command-line interface supports:

```bash
password-analyzer --no-hibp
password-analyzer --json --no-hibp
password-analyzer "password-to-check"
```

The `huehue` command is an alias for `password-analyzer`. Security implications related to interactive input, command-line arguments, and JSON output are described in Section 7.1.

## 7. Known Limitations and Security Considerations

The following points describe limitations and risks in the current implementation. They clarify the behavior of this version and identify areas that could be considered in future revisions; they do not imply that the current code has been modified.

### 7.1 Sensitive Information in Results and Command-line Use

The complete password is not stored in a dedicated `PasswordResult` field. However, the selected `Match` objects retain their matched text in `token`, and rule-violation entries can retain original values. These objects are included in the result and can be serialized by `to_dict()` and the CLI's `--json` option. As a result, JSON output may contain parts of the password and, in some cases, values corresponding to the complete password.

The current CLI uses `input()` for interactive password entry, which echoes typed characters in the terminal. Passwords supplied as positional command-line arguments may be visible in shell history or process listings. These behaviors represent potential exposure risks when the application is used in shared terminals, recorded sessions, scripts, or environments where process information is accessible.

Python does not provide a general guarantee that immutable string data can be securely erased from memory immediately. Accordingly, reducing references to sensitive values and limiting their serialization could reduce unintended retention, but should not be described as guaranteed secure memory wiping.

**Possible Future Improvements:** avoid retaining matched password fragments and original rule values in the public result when they are not needed; provide a way to serialize results without sensitive values; and use password input that does not echo typed characters in the terminal. These are potential improvements and are not implemented in the current version.

### 7.2 Built-in Blacklist

The current blacklist contains three example entries (`12345`, `admin`, and `password`) directly in the source code. It is active during analysis, and an exact match forces the final score to zero. It is not currently configurable through the public constructor or command-line interface.
