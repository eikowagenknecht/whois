import itertools
import string
import sys
import time
import whois
import logging
import os

# Configuration
TLD = ".de"
MIN_LENGTH = 1
MAX_LENGTH = 5
RESULT_FILE = "out/whoisresult.txt"
MUST_INCLUDE_SEQUENCE = ""  # Arbitrary string that must be in the domain name
WAIT_SECONDS = 2  # Initial wait time
MAX_RETRIES = 5  # Maximum number of retry attempts

# Character set configuration (set to True to include, False to exclude)
USE_LOWERCASE = True  # Include lowercase letters (a-z)
USE_DIGITS = True  # Include digits (0-9)
USE_HYPHEN = False  # Include hyphen (-)
USE_CUSTOM_CHARS = ""  # Add any additional custom characters here

# Logging configuration
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler(
            os.path.join(os.path.dirname(RESULT_FILE), "whois_log.txt")
        ),
    ],
)

# Enable ANSI escape sequences on Windows
try:
    import ctypes

    kernel32 = ctypes.windll.kernel32
    kernel32.SetConsoleMode(kernel32.GetStdHandle(-11), 7)
except (ImportError, AttributeError):
    pass  # Not on Windows or missing WinAPI support


def is_valid_domain_part(part):
    """Check if a domain part is valid."""
    if part.startswith("-") or part.endswith("-"):
        return False
    # Check for Punycode reserved patterns
    if len(part) >= 4 and part[2:4] == "--":
        return False
    return True


def generate_domains(characters, min_length, max_length, must_include_sequence):
    """Generate a set of domain names based on given parameters."""
    domains_to_check = set()
    domains_generated = 0

    logging.info(f"Generating domains with length {min_length} to {max_length}...")

    for r in range(min_length, max_length + 1):
        for name_parts in itertools.product(characters, repeat=r):
            url_part = "".join(name_parts)

            # Check for required sequence
            if must_include_sequence and must_include_sequence not in url_part:
                continue

            # Validate domain part
            if not is_valid_domain_part(url_part):
                continue

            domains_to_check.add(url_part + TLD)
            domains_generated += 1

            # Log progress periodically
            if domains_generated % 10000 == 0:
                logging.info(f"Generated {domains_generated} domains so far...")

    logging.info(f"Total domains to check: {len(domains_to_check)}")
    return domains_to_check


def check_domain(url, log_file):
    """Check if a domain exists and write the result to the log file."""
    retries = 0
    wait_seconds = WAIT_SECONDS

    while retries < MAX_RETRIES:
        try:
            sys.stdout.write(f"Checking {url}... ")
            sys.stdout.flush()

            res = whois.whois(url)

            if res.status is not None:
                logging.info(f"{url} exists!")
                sys.stdout.write("Exists!\n")
                return  # Domain exists, end function
            else:
                sys.stdout.write(f"Rate limit reached. Retrying in {wait_seconds}s\r")
                sys.stdout.flush()
                time.sleep(wait_seconds)
                wait_seconds *= 2  # Exponential backoff
                retries += 1
                sys.stdout.write("\x1b[2K\r")  # Clear line
        except whois.parser.PywhoisError:
            logging.info(f"{url} is likely unregistered.")
            sys.stdout.write("Unregistered!\n")
            print(url, file=log_file)
            log_file.flush()  # Ensure immediate write to file
            return  # Unregistered, end function
        except Exception as e:
            logging.error(f"An unexpected error occurred for {url}: {e}")
            sys.stdout.write(f"Error: {str(e)[:50]}... Retrying in {wait_seconds}s\r")
            retries += 1
            time.sleep(wait_seconds)
            wait_seconds *= 2
            sys.stdout.write("\x1b[2K\r")  # Clear line

    logging.error(f"Max retries reached for {url}. Skipping.")
    sys.stdout.write("Max retries reached. Skipping.\n")


def ensure_directory_exists(file_path):
    """Ensure the directory for the given file path exists."""
    directory = os.path.dirname(file_path)
    if directory and not os.path.exists(directory):
        os.makedirs(directory)
        logging.info(f"Created directory: {directory}")


def validate_configuration():
    """Validate the configuration settings."""
    if (
        not any([USE_LOWERCASE, USE_DIGITS, USE_HYPHEN])
        and not USE_CUSTOM_CHARS
    ):
        logging.error("Error: At least one character set must be enabled!")
        return False

    if MIN_LENGTH < 1:
        logging.error("Error: MIN_LENGTH must be at least 1!")
        return False

    if MAX_LENGTH < MIN_LENGTH:
        logging.error("Error: MAX_LENGTH must be greater than or equal to MIN_LENGTH!")
        return False

    # Simple TLD validation
    if not TLD.startswith("."):
        logging.warning("Warning: TLD should start with a dot (e.g., '.de')")

    return True


def main():
    # Validate configuration
    if not validate_configuration():
        sys.exit(1)

    # Ensure output directory exists
    ensure_directory_exists(RESULT_FILE)

    # Define character set based on configuration
    characters = []

    if USE_LOWERCASE:
        characters.extend(list(string.ascii_lowercase))

    if USE_DIGITS:
        characters.extend(list(string.digits))

    if USE_HYPHEN:
        characters.append("-")

    if USE_CUSTOM_CHARS:
        characters.extend(list(USE_CUSTOM_CHARS))

    # Ensure no duplicate characters
    characters = list(set(characters))

    # Log character set information
    logging.info(f"Using character set: {''.join(sorted(characters))}")

    # Add arbitrary string that must be in the domain name
    if MUST_INCLUDE_SEQUENCE and not any(
        MUST_INCLUDE_SEQUENCE in "".join(subset)
        for subset in itertools.permutations(characters, len(MUST_INCLUDE_SEQUENCE))
    ):
        characters.append(MUST_INCLUDE_SEQUENCE)
        logging.info(f"Added required sequence: {MUST_INCLUDE_SEQUENCE}")

    # Generate domains
    domains_to_check = generate_domains(
        characters, MIN_LENGTH, MAX_LENGTH, MUST_INCLUDE_SEQUENCE
    )

    # Show summary before starting
    logging.info(
        f"Starting WHOIS checks for {len(domains_to_check)} domains with TLD {TLD}"
    )
    logging.info(f"Domain length range: {MIN_LENGTH} to {MAX_LENGTH} characters")
    logging.info(f"Results will be saved to {RESULT_FILE}")

    # Calculate estimate of total time based on number of domains
    est_seconds_per_domain = WAIT_SECONDS * 1.5  # Rough estimate
    est_total_time = len(domains_to_check) * est_seconds_per_domain
    logging.info(
        f"Estimated total time: {est_total_time / 60:.1f} minutes (this is a rough estimate)"
    )

    start_time = time.time()

    with open(RESULT_FILE, "w", encoding="utf-8") as log_file:
        for index, url in enumerate(sorted(domains_to_check)):
            check_domain(url, log_file)

            # Show progress
            if (index + 1) % 10 == 0:
                elapsed = time.time() - start_time
                rate = (index + 1) / elapsed if elapsed > 0 else 0
                eta = (len(domains_to_check) - (index + 1)) / rate if rate > 0 else 0

                logging.info(
                    f"Progress: {index + 1}/{len(domains_to_check)} domains checked "
                    f"({(index + 1) / len(domains_to_check) * 100:.1f}%) "
                    f"- Rate: {rate:.2f} domains/sec - ETA: {eta / 60:.1f} minutes"
                )

    total_time = time.time() - start_time
    logging.info(f"WHOIS check completed in {total_time / 60:.2f} minutes")
    logging.info(f"Unregistered domains saved to {RESULT_FILE}")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        logging.info("Process interrupted by user. Exiting...")
        sys.exit(0)
    except Exception as e:
        logging.critical(f"Fatal error: {e}")
        sys.exit(1)
