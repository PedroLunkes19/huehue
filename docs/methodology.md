# Password Evaluation Methodology

## Overview

The huehue password evaluation methodology evaluates password security through multiple analysis techniques.

The evaluation process considers password compromise status, predictability, and resistance against common password attacks.


## Evaluation Criteria

The password evaluation is based on the following criteria:

- Presence in known data breaches;
- Use of predictable patterns;
- Similarity to common passwords;
- Estimated password complexity.


## Compromised Password Detection

Passwords found in known data breaches receive the lowest possible score.

A compromised password is considered insecure regardless of its length or character composition, since attackers can directly prioritize these credentials during attacks.


## Predictability Analysis

Passwords are analyzed for characteristics commonly exploited by attackers, including:

- Dictionary words;
- Common names;
- Sequential patterns;
- Repeated characters;
- Keyboard patterns;
- Date-based patterns.


## Strength Estimation

Passwords that are not identified as compromised are evaluated based on their resistance against guessing attacks.

The evaluation considers factors such as:

- Password complexity;
- Predictability;
- Estimated search space;
- Common attack strategies.


## Scoring System

The final score ranges from 0/4 to 4/4.

- 0/4: Password found in known data breaches.
- 1/4 - 4/4: Password not found in known breaches and evaluated according to the remaining security criteria.


## Guess Estimation (core/)

The local analysis follows zxcvbn and nbvcxz:

1. Each matcher result becomes a `Match` spanning `[i, j]`.
2. Every match has a guess estimate (`core/entropy.py`):
   - dictionary: `rank * uppercase_variations` (rank = position in the dataset, which is sorted by popularity; unordered datasets such as `eff_large` use the dataset size);
   - sequence, repeat, date and keyboard (spatial) follow the zxcvbn formulas;
   - bruteforce: `cardinality ^ length`, where the cardinality is the sum of the character pools used (a-z 26, A-Z 26, 0-9 10, symbols 33, other 100), as in nbvcxz.
3. A dynamic programming search (`core/scoring.py`) picks the non-overlapping sequence minimizing `l! * Product(guesses) + 10000^(l-1)`; uncovered gaps are filled with bruteforce matches.
4. `guesses` is converted to a 0-4 score with the thresholds `1e3`, `1e6`, `1e8` and `1e10`.
5. Final score: 0 if the password is breached or blacklisted; otherwise the raw score clamped to a minimum of 1.
6. Crack times are estimated for the zxcvbn attack scenarios (with human readable output) and, optionally, for nbvcxz-style guess types (`time_to_crack`).
