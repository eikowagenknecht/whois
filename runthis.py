# Include ctypes if you're on Windows
import ctypes
import itertools
import string
import sys
import time

import whois

# Enable ANSI escape sequences on Windows
kernel32 = ctypes.windll.kernel32
kernel32.SetConsoleMode(kernel32.GetStdHandle(-11), 7)

# Directory must exist, file doesn't have to.
TLD = ".de"
MIN_LENGTH = 1
MAX_LENGTH = 5
RESULT_FILE = "c:\\Temp\\whoisresult.txt"
"""Where to write the results to."""
MUST_INCLUDE_SEQUENCE = "" 
""" Arbitrary string that must be in the domain name. Leave empty if you don't need it."""

def main():
    characters = list(string.ascii_lowercase)
    characters.extend(list(string.digits))
    characters.append("-")

    # Add arbitrary string that must be in the domain name
    if MUST_INCLUDE_SEQUENCE:
        characters.append(MUST_INCLUDE_SEQUENCE)

    domains_to_check = set()

    for r in range(MIN_LENGTH, MAX_LENGTH):
        for name in itertools.product(characters, repeat=r):
            url = "".join(name)

            # Only use the first MAX_LENGTH characters
            url = url[:MAX_LENGTH]
            
            # That may exclude the needed sequence, so skip those
            if MUST_INCLUDE_SEQUENCE not in url:
                continue

            # Skip invalid domain names
            if url.startswith("-") or url.endswith("-"):
                continue

            # Also skip if length >= 4 and third and fourth character
            # are "-". Those are reserved for Punycode.
            if len(url) >= 4 and url[2] == "-" and url[3] == "-":
                continue

            url += TLD

            domains_to_check.add(url)

    with open(RESULT_FILE, "w") as log:
        for url in sorted(domains_to_check):
            wait_seconds = 2
            try:
                success = False
                while not success:
                    print("Checking " + url + " ... ", end="")
                    res = whois.whois(url)
                    if res.status is not None:
                        success = True
                        print("Exists!")
                    else:
                        print(
                            "Probably the rate limit has been reached.",
                            f"Trying again in {wait_seconds}s.",
                            end="\r",
                        )
                        time.sleep(wait_seconds)
                        sys.stdout.write("\x1b[2K\r")
                        wait_seconds = wait_seconds * 2
            except whois.parser.PywhoisError:
                print("Exception! (probably unregistered name here)")
                print(url, file=log)


if __name__ == "__main__":
    main()
