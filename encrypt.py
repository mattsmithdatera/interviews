#!/usr/bin/env python

import argparse
import base64
import io
import os
import shlex
import subprocess
import sys

import cryptography.fernet as fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

SUCCESS = 0
FAILURE = 1

EXCLUDE = ["encrypt.py"]
INCLUDE = ["*.py"]


def main(args):
    # Not gonna salt because there's only going to be one password
    # and we don't really care if somebody tries rainbow tables.
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        iterations=100000,
        salt=("0" * 16).encode('utf-8'),
        backend=default_backend())
    key = base64.urlsafe_b64encode(kdf.derive(args.key))
    fern = fernet.Fernet(key)
    output_list = []
    for inc in INCLUDE:
        result = subprocess.check_output(shlex.split(
            "find . -name '{}'".format(inc))).decode('utf-8')
        output_list.extend(str(result).strip().split("\n"))
    files = [elem for elem in output_list
             if os.path.basename(elem) not in EXCLUDE]
    if args.encrypt:
        for file in files:
            with io.open(file, 'rb') as f:
                token = fern.encrypt(f.read())
            with io.open(file, 'wb') as f:
                f.write(token)
        return SUCCESS
    elif args.decrypt:
        for file in files:
            with io.open(file, 'rb') as f:
                out = fern.decrypt(f.read())
            with io.open(file, 'wb') as f:
                f.write(out)
        return SUCCESS
    else:
        print("Encrypt/Decrypt option not specified")
        return FAILURE

if __name__ == "__main__":
    parser = argparse.ArgumentParser("Accepts the key via stdin as well")
    parser.add_argument("key", nargs='*', default=None)
    parser.add_argument("-e", "--encrypt", action="store_true")
    parser.add_argument("-d", "--decrypt", action="store_true")

    args = parser.parse_args()
    if not args.key:
        args.key = sys.stdin.read().strip().encode('utf-8')
    sys.exit(main(args))
