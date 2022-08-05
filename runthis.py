# include ctypes if you're on Windows
import ctypes
import itertools
import string
import sys
import time

import whois

kernel32 = ctypes.windll.kernel32
kernel32.SetConsoleMode(kernel32.GetStdHandle(-11), 7)

# Directory must exist, file doesn't have to.
TLD = ".de"
MIN_LENGTH = 1
MAX_LENGTH = 5
RESULT_FILE = "c:\\Temp\\whoisresult.txt"  

def main():
    characters = list(string.ascii_lowercase)
    characters.extend(list(string.digits))
    characters.append("-")

    with open(RESULT_FILE, "w") as log:
        for r in range(MIN_LENGTH, MAX_LENGTH):
            for name in itertools.product(
                characters, repeat=r
            ):
                url = "".join(name)
                if url.startswith("-") or url.endswith("-"):
                    # Invalid name, skip
                    
                    continue
                if len(url) >= 4 and url[2] == "-" and url[3] == "-":
                    # Also skip if length >= 4 and third and fourth character are "-".
                    # Those are reserved for special character representations.
                    continue

                url += TLD

                wait_seconds = 2
                try:
                    success = False
                    while success == False:
                        print("Checking " + url + " ... ", end="")
                        res = whois.whois(url)
                        if res.status != None:
                            success = True
                            print("Exists!")
                        else:
                            print(
                                "Probably the rate limit has been reached. Trying again in "
                                + str(wait_seconds)
                                + "s.",
                                end="\r",
                            )
                            time.sleep(wait_seconds)
                            sys.stdout.write("\x1b[2K\r")
                            wait_seconds = wait_seconds * 2
                except whois.parser.PywhoisError as e:
                    print("Exception! (probably unregistered name here)")
                    print(url, file=log)


if __name__ == "__main__":
    main()
