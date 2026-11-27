# Evaluation Methodology

This document describes how huehue evaluates a password. The evaluation follows the models used by [zxcvbn](https://github.com/dropbox/zxcvbn) and [nbvcxz](https://github.com/GoSimpleLLC/nbvcxz), with some custom components. The differences among the three evaluators and huehue's limitations are described in Section 7. The referenced source code files are located in `src/password_analyzer/`.

## 1. Overview

huehue calculates the **number of guesses** an attacker would need to crack a password. The attacker is modeled as someone who tests the most likely password candidates first: common passwords, names, words, dates, sequences, and keyboard patterns. The score and crack time are calculated based on this number.

Evaluation steps:

1. Breach lookup (HIBP).
2. Rule checking (blacklist and composition).
3. Password pattern detection.
4. Calculation of the number of guesses for each pattern.
5. Selection of the password decomposition with the lowest number of guesses.
6. Conversion of the total into a score (0 to 4) and a crack time.

huehue also reports `entropy_bits`, which is `log₂(guesses)`. It is simply another scale for the same number: each bit doubles the number of guesses.

## 2. Breach Lookup

huehue queries the Have I Been Pwned Pwned Passwords API. Only the first 5 characters of the password's SHA-1 hash are sent, and the remaining comparison is performed locally (k-anonymity). The process is described in [`hibp_EN.md`](hibp_EN.md).

A password found in a breach receives a score of 0, regardless of its length or composition. If the query fails (for example, due to a lack of internet connection), the breach status is marked as unknown and the local analysis continues.

This step is specific to huehue.

## 3. Rules

- **Blacklist** (`rules/blacklist.py`): passwords included in the list receive a score of 0.
- **Composition** (`rules/composition.py`): checks the minimum length (8) and the presence of uppercase letters, lowercase letters, digits, and special characters (including spaces). Violations generate warnings and **do not affect the score**.

## 4. Patterns and Number of Guesses

Each detected pattern is a segment of the password, with a starting and ending position. The number of guesses for a segment is the number of candidates an attacker would try, in order of likelihood, before reaching it. The calculation is implemented in `core/entropy.py`; detection is implemented in `matchers/`.

| Pattern | What it detects | Number of guesses | Formula Source |
|---|---|---|---|
| Dictionary | A segment of 3+ characters present in a list | list position × capitalization variations | zxcvbn |
| Sequence | `123`, `987` | base × length | zxcvbn |
| Keyboard | `qwerty`, `asdf`, `1234567890` | sum over the possible lengths (4.3) | zxcvbn |
| Repetition | `aaa`, `!!!!` | character cost × number of repetitions | zxcvbn |
| Date | `31122026`, `31/12/26` | year difference × 365 | zxcvbn |
| Brute force | A segment with no recognized pattern | alphabet size ^ segment length | nbvcxz |

### 4.0 Minimum Guess Count for a Segment

A segment that **does not** cover the entire password is never assigned fewer than **10** guesses (1 character) or **50** guesses (2 or more characters). Without this minimum, a segment such as `Maria` (rank 1 in the list) would count as 2 guesses and reduce the total too much. The brute-force segment uses a minimum that is one unit higher (11 and 51), so that, if two matches tie for the same segment, the dictionary, sequence, or other pattern is selected.

Source: zxcvbn → constants in `scoring.coffee`:

`MIN_SUBMATCH_GUESSES_SINGLE_CHAR` (10)

`MIN_SUBMATCH_GUESSES_MULTI_CHAR` (50), in `scoring.coffee`.

### 4.1 Dictionary

**Detection.** For each dataset, huehue searches the password for any segment of 3 or more characters that matches an entry in the dataset. If the entire password is an entry, that is the result. Otherwise, among the matching segments, the selection follows this order:

1. Segment with a known frequency;
2. Highest frequency;
3. Greatest length.

Since the search returns only one segment per dataset, huehue repeats the search in the text to the left and right of the segment found, so that the decomposition selection (Section 5) has all candidates available.

Datasets used (`data/`):

| Dataset | Content | File order | Case-insensitive matching |
|---|---|---|---|
| `common_passwords` | Common passwords | Most to least common | No |
| `names_brazil` | Brazilian first names | Most to least common | Yes |
| `surnames_brazil` | Brazilian surnames | Most to least common | Yes |
| `names_english` | English first names | Most to least common | Yes |
| `surnames_english` | English surnames | Most to least common | Yes |
| `english` | English words | Most to least common | No |
| `eff_large` | Word list for passphrases | Alphabetical | No |

**Formula.**

```text
guesses = list_position × capitalization_variations
```

- **List position (rank).** An attacker who tests entries from most to least common reaches the entry at position *n* after *n* guesses. In datasets whose ordering does not indicate frequency, the rank is the size of the entire list.
- **Capitalization variations.** These represent the different ways of writing the same word using uppercase and lowercase letters:

| Word format | Factor |
|---|---|
| All lowercase (`maria`) | 1 |
| Only the first letter (`Maria`), only the last letter (`mariA`), or all letters (`MARIA`) uppercase | 2 |
| Other combinations (`pAsswOrd`) | requires calculation |

For the other combinations (the third row of the table), the formula is:

```text
variations = Σ C(U + L, i), for i from 1 to m
```

Variables:

- `U`: number of uppercase letters in the word.
- `L`: number of lowercase letters in the word. `U + L` is the total number of letters.
- `m = min(U, L)`: the smaller of `U` and `L`.
- `i`: number of uppercase letters in each counted case, from 1 to `m`.
- `C(n, i)`: binomial coefficient, the number of ways to choose `i` letters from `n`. It is calculated as `C(n, i) = n! ÷ (i! × (n − i)!)`.

Example using `pAsswOrd`: `U = 2` (A, O), `L = 6` (p, s, s, w, r, d), `U + L = 8`, and `m = 2`.

```text
variations = C(8, 1) + C(8, 2)
           = 8 + 28
           = 36
```

The three common formats in the table (first letter, last letter, or all letters uppercase) have values inspired by zxcvbn and receive a factor of 2 because they are common variations.

Example: `Maria` → 1 × 2 = 2, which is raised to 50 by the segment minimum (4.0).

Source: zxcvbn, `dictionary_guesses` and `uppercase_variations`, in `scoring.coffee`.

### 4.2 Sequence

**Detection.** huehue searches for sequences of 3 consecutive digits, either ascending (`012`, `123`, ..., `789`) or descending (`987`, `876`, ..., `210`). Only the first occurrence in the password is considered. Longer sequences, such as `123456`, are handled by the keyboard detector (4.3).

**Formula.**

```text
guesses = base × segment_length
```

| First character | Base |
|---|---|
| `a`, `A`, `z`, `Z`, `0`, `1`, or `9` | 4 |
| Any other digit | 10 |
| Any other character | 26 |

If the sequence is descending, the base is multiplied by 2 because the attacker must also test the reverse direction. The smaller bases correspond to starting points that people commonly choose (the beginning or end of the alphabet, `0`, `1`, and `9`).

Examples: `123` → 4 × 3 = **12**. `987` → (4 × 2) × 3 = **24**. `456` → 10 × 3 = **30**.

Source: zxcvbn, `sequence_guesses`, in `scoring.coffee`.

### 4.3 Keyboard

**Detection.** huehue searches for segments of 3 or more consecutive keys in one of the four rows of a QWERTY keyboard, in forward or reverse order, without distinguishing between uppercase and lowercase letters:

```text
1234567890
qwertyuiop
asdfghjkl
zxcvbnm
```

**Formula.**

```text
guesses = (L − 1) × s × d
```

- `L`: segment length, in keys. The attacker tests segments of every length from 2 to `L`, and each length contributes `s × d` guesses. This is why the factor is `L − 1`.
- `s`: number of keys at which a segment can start (47 on QWERTY).
- `d`: average number of neighboring keys for a key (≈ 4.6 on QWERTY). This represents the attacker's options for the next key.

Example: a segment of 5 consecutive keys (`L = 5`) → 4 × 216 = **864**.

**Uppercase letters (Shift).** If the segment contains uppercase letters, the result is multiplied by a factor:

```text
if all keys use Shift:     factor = 2
otherwise:                 factor = C(S + N, 1) + ... + C(S + N, m)

where m = minimum of S and N
```

- `S`: number of keys using Shift (uppercase letters) in the segment.
- `N`: number of keys not using Shift (`N = L − S`).
- `C(n, i)`: number of ways to choose `i` keys from `n`, as in Section 4.1.

Example: `asDfg` has `S = 1` and `N = 4`, so `m = 1` and the factor is `C(5, 1) = 5`. The result is 864 × 5 = **4,320**.

Source: zxcvbn, `spatial_guesses`, in `scoring.coffee`. The values 47 and ≈ 4.6 come from the zxcvbn keyboard adjacency graph (`adjacency_graphs.coffee`), generated by `scripts/build_keyboard_adjacency_graph.py`.

### 4.4 Repetition

**Detection.** huehue searches for the same character repeated 3 or more times consecutively (`aaa`, `111`, `!!!!`). Only the first occurrence is considered.

**Formula.**

```text
guesses = character_cost × number_of_repetitions
```

The character cost is the cost of guessing a single character: the size of that character's alphabet, as defined in Section 4.6, with a minimum of 11. The attacker guesses the character once and then only needs to choose how many times it is repeated.

Examples: `aaaa` → 26 × 4 = **104**. `!!!!!` → 33 × 5 = **165**. `1111` → 11 × 4 = **44** (the digit alphabet has 10 characters, and the minimum is 11).

Source: zxcvbn, `repeat_guesses`, in `scoring.coffee`. In zxcvbn, the base cost is that of the repeated block, which may contain more than one character. In huehue, the block is always a single character (Section 7).

### 4.5 Date

**Detection.** huehue searches for dates in day, month, and year format, with a two- or four-digit year, and with no digits immediately before or after the date:

| Format | Example |
|---|---|
| `DDMMYY` | `311226` |
| `DDMMYYYY` | `31122026` |
| `DD/MM/YY` | `31/12/26` |
| `DD/MM/YYYY` | `31/12/2026` |

Only the first date in the password is considered. Two-digit years are converted as follows: `00–49` become 2000–2049, and `50–99` become 1950–1999.

Detection checks the numeric ranges for the day (01–31) and month (01–12), but does not verify whether the date exists in the calendar. Therefore, combinations such as `31/02/26` may also be recognized.

**Formula.**

```text
guesses = max(|year − current_year|, 20) × 365
if a separator is present: guesses × 4
```

- `|year − current_year|`: distance between the date's year and the current year. Dates close to the present are more likely, so they require fewer guesses.
- `max(..., 20)`: the attacker tests at least a 20-year window, even if the date is from the current year.
- `× 365`: days in a year.
- `× 4`: represents the choice of separator, when one is present.

Examples (in 2026): `31122026` → 20 × 365 = **7,300**. `31/12/2026` → 7,300 × 4 = **29,200**. `31/12/1990` → 36 × 365 × 4 = **52,560**. The current year is part of the calculation, so the values change from year to year.

Source: zxcvbn, `date_guesses`, with the `MIN_YEAR_SPACE` (20) and `REFERENCE_YEAR` constants in `scoring.coffee`.

### 4.6 Brute Force

Password segments not covered by any pattern are filled with brute-force matches during the decomposition selection process (Section 5).

**Formula.**

```text
guesses = alphabet_size ^ segment_length
```

The segment can be any combination of characters from the alphabet, so there are `alphabet_size` options for each position. The **alphabet size** is the sum of the character groups present in the segment:

| Group | Size |
|---|---|
| Lowercase letters (a–z) | 26 |
| Uppercase letters (A–Z) | 26 |
| Digits (0–9) | 10 |
| ASCII symbols (including spaces) | 33 |
| Any other character (accented characters, other alphabets) | 100 |

Examples:

- `xqzvjkpmw`: 9 lowercase letters → 26⁹ = **5,429,503,678,976** (≈ 10¹²·⁷).
- `Zx9!`: uppercase, lowercase, digit, and symbol → 26 + 26 + 10 + 33 = 95 → 95⁴ = **81,450,625**.
- `!`: 1 symbol → 33¹ = **33**.

By default, the alphabet is calculated separately for each brute-force segment (`bruteforce_scope="token"`). With `bruteforce_scope="password"`, the alphabet of the entire password is used, which increases the value when the password combines several character groups.

Source: nbvcxz (`BruteForceUtil` class). The formula `alphabet ^ length` and the segment minimum come from zxcvbn (`bruteforce_guesses`, in `scoring.coffee`).

## 5. Password Decomposition Selection

The detected patterns may overlap. huehue selects the set of non-overlapping segments that covers the entire password and has the **lowest value** for:

```text
g = l! × (product of segment guesses) + 10000^(l − 1)
```

where `l` is the number of segments. The function is `most_guessable_match_sequence`, in `core/scoring.py`.

- **Product:** the choices for each segment are independent, so their values are multiplied.
- **`l!`:** represents the possible orderings of the `l` segments.
- **`10000^(l − 1)`:** penalizes sequences with more segments. This prevents splitting the password into many small segments from artificially reducing the total.

Segments not covered by any pattern are filled with brute-force matches. The search uses dynamic programming: for each password position and each number of segments, it stores the best sequence found and reuses that result for subsequent positions.

### Example: `pedro123`

| Segment | Pattern | Calculation | Guesses |
|---|---|---|---|
| `pedro` | dictionary (`names_brazil`, rank 9) | 9 × 1 = 9; minimum of 50 | 50 |
| `123` | sequence | 4 × 3 = 12; minimum of 50 | 50 |

With `l = 2`:

```text
g = 2! × (50 × 50) + 10000¹ = 5,000 + 10,000 = 15,000  (≈ 10^4.2)
```

Result: raw score 1 (between 10³ and 10⁶ guesses).

## 6. Score, Crack Time, and Warnings

### 6.1 Score

The raw score (`raw_score`) is determined by the number of guesses:

| Guesses | Raw score |
|---|---|
| < 10³ | 0 |
| < 10⁶ | 1 |
| < 10⁸ | 2 |
| < 10¹⁰ | 3 |
| ≥ 10¹⁰ | 4 |

The table thresholds are compared with an offset of 5. For example, score 0 applies to fewer than 1,005 guesses, rather than fewer than 1,000. This keeps values immediately above an exact power of 10 in the same range.

These ranges and the offset of 5 (`SCORE_DELTA`) come from zxcvbn (`guesses_to_score`).

The final score (`score`) is:

- **0**, if the password was found in a breach or is in the blacklist;
- `max(raw_score, 1)` in all other cases (so that score 0 is exclusive to breached or blacklisted passwords).

Labels:

| Score | Label |
|---|---|
| 0 | very weak |
| 1 | weak |
| 2 | fair |
| 3 | strong |
| 4 | very strong |

Along with the score, warnings and suggestions are provided depending on which patterns were detected in the password. For example, if the password contains a proper name, it receives a warning about proper names; if the password has fewer than 12 characters, it receives a suggestion to make it longer.

### 6.2 Crack Time

The time is `guesses ÷ attack speed`. huehue uses the four zxcvbn scenarios:

| Scenario | Speed |
|---|---|
| `online_throttling_100_per_hour` | 100 per hour |
| `online_no_throttling_10_per_second` | 10 per second |
| `offline_slow_hashing_1e4_per_second` | 10⁴ per second |
| `offline_fast_hashing_1e10_per_second` | 10¹⁰ per second |

These speeds are assumptions used by zxcvbn as reference values. To consult them, see `scenario_definitions` in `src/time_estimates.coffee`, in the [official zxcvbn repository](https://github.com/dropbox/zxcvbn/blob/master/src/time_estimates.coffee).

Example: 15,000 guesses at 10 per second → 1,500 s ≈ 25 minutes.

The `core/scoring.py` file also defines `GUESS_TYPES`, with reference speeds for different hash types, inspired by nbvcxz. The table below shows the values defined in the code:

| Type | Speed (guesses per second) |
|---|---:|
| `OFFLINE_MD5` | 250,375,000,000 |
| `OFFLINE_SHA1` | 85,963,750,000 |
| `OFFLINE_SHA512` | 10,780,875,000 |
| `OFFLINE_BCRYPT_5` | 130,875 |
| `OFFLINE_BCRYPT_10` | 4,129 |
| `OFFLINE_BCRYPT_12` | 1,033 |
| `OFFLINE_BCRYPT_14` | 259 |
| `ONLINE_UNTHROTTLED` | 100 |
| `ONLINE_THROTTLED` | 2 |

These values are reference values used by `time_to_crack()` and can be adjusted to match the hardware.

The `analyze()` function uses the four `ATTACK_SCENARIOS` described above, not these hash-type-specific values.

## 7. Differences Between the Evaluators and huehue's Limitations

### 7.1 Comparison

huehue is based on zxcvbn and nbvcxz and does not fully reimplement either of them. The nbvcxz README states that strict compatibility with zxcvbn is not one of its goals.

| Aspect | zxcvbn | nbvcxz | huehue |
|---|---|---|---|
| Language | CoffeeScript / JavaScript | Java | Python |
| Main output | Number of guesses and score from 0 to 4 | Entropy, with a configurable minimum value | Number of guesses and score from 0 to 4 |
| Dictionaries | Common passwords, names, and English words | Multiple configurable dictionaries, ranked or unranked | Common passwords, first names, and surnames (Brazilian and English), English words |
| Approximate matching (Levenshtein distance) | No | Yes, configurable | No |
| Letter substitutions (`p4ssw0rd`) and reversed words | Yes | — | No |
| Keyboard patterns | Keyboard paths, including turns | Yes | Straight lines only |
| Repetition | Characters and blocks (`abcabc`) | Characters and character sets | Single character only |
| Dates | Various formats, with separators | Dates and years | `DDMMYY` and `DDMMYYYY`, with or without `/` |
| Brute force | Fixed alphabet of 10 | Alphabet based on character groups | Alphabet based on character groups |
| Decomposition search | `l! × product + D^(l−1)` | Combination with the lowest entropy | Same as zxcvbn |
| Crack time | 4 attack scenarios | Configurable hash types | 4 zxcvbn scenarios; optional hash types |
| Breach lookup (HIBP) | No | — | Yes |
| Blacklist and composition rules | No | Exclusion dictionaries and minimum entropy | Yes |

"—" indicates that the information was not identified in the project documentation reviewed; it does not necessarily mean that the feature does not exist.

### 7.2 huehue's Limitations

**Undetected patterns**

- Letter substitutions with numbers and symbols (`p4ssw0rd`, `s3nh@`).
- Words written backwards.
- Words containing typos or minor variations.
- Letter sequences (`abc`, `xyz`). Only numeric sequences of 3 digits are detected.
- Repeated blocks (`abcabc`).
- Diagonal or curved keyboard patterns. Only straight lines across the 4 rows are detected (`1234567890`, `qwertyuiop`, `asdfghjkl`, `zxcvbnm`).
- Dates in other formats, for example, using `-` or `.` as separators, or `YYYYMMDD`.

**Detection**

- The date, repetition, sequence, and keyboard detectors return **only one occurrence** per password.
- The dictionaries contain Brazilian and English first names and surnames, but only **English** common words. Portuguese words are not recognized by the word dictionaries and are therefore treated as brute-force segments.
- Pattern analysis and guess estimation consider only the first 128 characters of the password.
- HIBP lookup, blacklist checking, and composition rules use the entire password.
