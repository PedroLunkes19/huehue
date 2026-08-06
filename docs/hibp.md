# Have I Been Pwned Integration

## Overview

The project uses the Have I Been Pwned Pwned Passwords API to check whether a password has appeared in known data breaches.

The implementation uses the k-anonymity model to avoid sending the original password.


## Verification Process

1. The password is hashed locally using SHA-1.

2. The first 5 characters of the hash are sent to the API.

3. The API returns all hashes with the same prefix.

4. The application searches locally for the remaining hash suffix.

5. If the suffix is found, the password is considered compromised.


## Example

Password:

123456

SHA-1:

7C4A8D09CA3762AF61E59520943DC26494F8941B


Prefix sent:

7C4A8


Suffix checked locally:

D09CA3762AF61E59520943DC26494F8941B