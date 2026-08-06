## Overview

huehue is a python-based application designed to evaluate password security.

## Project Structure

The project follows a modular architecture, where each module is responsible for a specific part of the password evaluation process.
```
huehue/
│
├── src/
│   └── password_analyzer/
│       ├── api/
│       ├── core/
│       ├── matchers/
│       ├── rules/
│       ├── models/
│       ├── data/
│       └── utils/
│
├── tests/
│
├── examples/
│
├── docs/
│
├── pyproject.toml
├── requirements.txt
└── README.md
```

## Module Responsibilities

### api/

Responsible for communication with external services.

Currently implements the Have I Been Pwned (HIBP) API integration using the k-anonymity model to check if passwords have appeared in known data breaches.


### core/

Contains the main password evaluation logic.

Responsible for orchestrating the analysis workflow, combining the results from different security checks, and generating the final password evaluation.


### matchers/

Contains the algorithms responsible for detecting predictable password patterns.

Examples:

- Common words
- Dictionary matches
- Repeated characters
- Keyboard patterns
- Sequential patterns
- Date patterns


### rules/

Contains security rules and constraints used during password evaluation.

Examples:

- Character composition rules
- Password blacklist rules
- Minimum length requirements


### models/

Contains data structures used to represent application entities and analysis results.


### data/

Contains datasets used during password analysis.

Examples:

- Common passwords
- Names
- Surnames
- Custom dictionaries


### utils/

Contains auxiliary functions shared between different modules.

Examples:

- Data loading
- Common helper functions


### examples/

Contains example scripts demonstrating how to use the application.


### tests/

Contains automated tests to verify the functionality of different application modules.



## Architecture Flow
```
Password Input

        |
        v

HIBP Check

        |
        |
        +---- Password found
        |          |
        |          v
        |       Score 0/4
        |
        v

Local Analysis

        |
        +---- Dictionary matching
        |
        +---- Pattern detection
        |
        +---- Entropy estimation

        |
        v

Final Score (1-4/4)
```
