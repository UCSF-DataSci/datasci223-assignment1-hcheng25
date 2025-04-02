#!/usr/bin/env python3
"""
Email Hasher Script

This script takes an email address as a command line argument,
hashes it using the SHA-256 algorithm, and writes the hash to a file.

Usage:
    python email_hasher.py <email_address>

Example:
    python email_hasher.py example@email.com
"""

import sys
import hashlib
import re

def hash_email(email):
    encoded = str.encode(email)
    return(hashlib.sha256(encoded).hexdigest())
    # 1. Convert the email string to bytes
    # 2. Create a SHA-256 hash of the email
    # 3. Return the hash in hexadecimal format

def write_hash_to_file(hash_value, filename="hash.email"):
    with open(filename, 'wt') as fout:
        print(hash_value, file=fout)
    # 1. Open the file in write mode
    # 2. Write the hash value to the file
    # 3. Close the file

def main():
    email = sys.argv[1]
    try:
        hash = hash_email(email)
        write_hash_to_file(hash_value=hash, filename='hash.email')
    except:
        exit('Argument is not valid')
    # 1. Check if an email address was provided as a command line argument
    # 2. If not, print an error message and exit with a non-zero status
    # 3. If yes, hash the email address
    # 4. Write the hash to a file named "hash.email"

if __name__ == "__main__":
    main()
