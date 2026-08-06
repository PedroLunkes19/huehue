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
