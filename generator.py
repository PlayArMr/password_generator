"""
generator.py - Core Generation Engine for CS50x Password Generator.

Data structures and logic for generating cryptographically secure random
passwords and passphrases using Python's `secrets` module.
"""

from dataclasses import dataclass
import os
import secrets
import string
from typing import List, Tuple

DEFAULT_AMBIGUOUS_CHARS = "0O1lI|"
DEFAULT_SPECIAL_CHARS = "!@#$%^&*()-_=+[]{}|;:,.<>?"


@dataclass
class PasswordConfig:
    """Configuration settings for random password generation."""
    length: int = 16
    include_uppercase: bool = True
    include_lowercase: bool = True
    include_digits: bool = True
    include_special: bool = True
    exclude_ambiguous: bool = True
    count: int = 1


@dataclass
class PassphraseConfig:
    """Configuration settings for passphrase generation."""
    num_words: int = 4
    separator: str = "-"
    capitalize: bool = False
    include_number: bool = False
    include_symbol: bool = False
    wordlist_path: str = "wordlist.txt"
    count: int = 1


def get_character_pools(config: PasswordConfig) -> Tuple[str, List[str]]:
    """
    Builds the active character pools based on user configuration.

    Filters out ambiguous characters if `exclude_ambiguous` is True.

    Returns:
        A tuple:
        - combined_pool (str): All permitted characters concatenated.
        - active_class_pools (List[str]): List of distinct non-empty strings,
          each containing permitted characters for one selected class.
    """
    def filter_chars(chars: str) -> str:
        if config.exclude_ambiguous:
            return "".join(ch for ch in chars if ch not in DEFAULT_AMBIGUOUS_CHARS)
        return chars

    active_class_pools: List[str] = []

    if config.include_uppercase:
        pool = filter_chars(string.ascii_uppercase)
        if pool:
            active_class_pools.append(pool)

    if config.include_lowercase:
        pool = filter_chars(string.ascii_lowercase)
        if pool:
            active_class_pools.append(pool)

    if config.include_digits:
        pool = filter_chars(string.digits)
        if pool:
            active_class_pools.append(pool)

    if config.include_special:
        pool = filter_chars(DEFAULT_SPECIAL_CHARS)
        if pool:
            active_class_pools.append(pool)

    combined_pool = "".join(active_class_pools)
    return combined_pool, active_class_pools


def load_wordlist(filepath: str) -> List[str]:
    """
    Loads and cleans a wordlist from the specified file path.

    Each line is stripped of whitespace. Lines starting with '#' and
    blank lines are ignored.
    """
    if not os.path.isabs(filepath):
        script_dir = os.path.dirname(os.path.abspath(__file__))
        candidate_path = os.path.join(script_dir, filepath)
        if os.path.exists(candidate_path):
            filepath = candidate_path

    if not os.path.isfile(filepath):
        raise FileNotFoundError(f"Wordlist file not found at: {filepath}")

    words: List[str] = []
    with open(filepath, "r", encoding="utf-8") as f:
        for line in f:
            cleaned = line.strip()
            if cleaned and not cleaned.startswith("#"):
                words.append(cleaned)

    if not words:
        raise ValueError(f"Wordlist at '{filepath}' contains no valid words.")

    return words


def validate_passphrase_config(config: PassphraseConfig, wordlist: List[str]) -> None:
    """Validates passphrase configuration parameters."""
    if not isinstance(config.num_words, int) or config.num_words <= 0:
        raise ValueError("Passphrase word count must be a positive integer.")

    if not isinstance(config.count, int) or config.count <= 0:
        raise ValueError("Passphrase batch count must be a positive integer.")

    if not isinstance(config.separator, str):
        raise ValueError("Passphrase separator must be a string.")

    if not wordlist:
        raise ValueError("Wordlist cannot be empty.")

    if len(wordlist) < 10:
        raise ValueError(
            f"Wordlist has only {len(wordlist)} words; at least 10 words are required for security."
        )

    min_expected_length = config.num_words + (len(config.separator) * (config.num_words - 1))
    if min_expected_length <= 0:
        raise ValueError("Calculated passphrase minimum length is invalid.")


def secure_random_index(limit: int) -> int:
    """
    Select an integer index uniformly at random in the range [0, limit) using `secrets`.

    Raises:
        ValueError: If `limit` is not an integer greater than 0.
    """
    if not isinstance(limit, int) or isinstance(limit, bool) or limit <= 0:
        raise ValueError("limit must be an integer greater than 0.")
    return secrets.randbelow(limit)


def validate_password_config(config: PasswordConfig) -> None:
    """
    Validates that a PasswordConfig instance contains consistent and feasible settings.

    Raises:
        ValueError: If length or count is not a positive integer, no character
            class is usable, or length is too short to represent every active class.
    """
    for name, value in (("length", config.length), ("count", config.count)):
        if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
            raise ValueError(f"Password {name} must be a positive integer.")

    enabled_classes = sum(
        (
            config.include_uppercase,
            config.include_lowercase,
            config.include_digits,
            config.include_special,
        )
    )
    if enabled_classes == 0:
        raise ValueError("At least one character class must be enabled.")

    _, active_pools = get_character_pools(config)
    if len(active_pools) < enabled_classes:
        raise ValueError("An enabled character class has no characters left after filtering.")

    if config.length < len(active_pools):
        raise ValueError(
            f"Password length must be at least {len(active_pools)} "
            f"to include every enabled character class."
        )


def generate_password(config: PasswordConfig) -> str:
    """
    Generates a single cryptographically secure password satisfying the configuration.

    Every active character class is guaranteed at least one character, the rest
    is drawn from the combined pool, and the result is shuffled with a
    Fisher-Yates shuffle driven by `secure_random_index`.
    """
    validate_password_config(config)
    combined_pool, active_pools = get_character_pools(config)

    chars = [pool[secure_random_index(len(pool))] for pool in active_pools]
    chars.extend(
        combined_pool[secure_random_index(len(combined_pool))]
        for _ in range(config.length - len(chars))
    )

    for i in range(len(chars) - 1, 0, -1):
        j = secure_random_index(i + 1)
        chars[i], chars[j] = chars[j], chars[i]

    return "".join(chars)


def generate_passwords(config: PasswordConfig) -> List[str]:
    """Generates a batch of unique random passwords."""
    passwords: List[str] = []
    seen = set()
    max_attempts = max(config.count * 15, 100)
    attempts = 0

    while len(passwords) < config.count and attempts < max_attempts:
        pwd = generate_password(config)
        attempts += 1
        if pwd not in seen:
            seen.add(pwd)
            passwords.append(pwd)

    if len(passwords) < config.count:
        raise RuntimeError(
            f"Could only generate {len(passwords)} unique passwords out of {config.count} "
            f"requested (attempted {attempts} times). Consider increasing length or pool size."
        )

    return passwords


def generate_passphrase(config: PassphraseConfig, wordlist: List[str]) -> str:
    """Generates a cryptographically secure passphrase from a wordlist."""
    validate_passphrase_config(config, wordlist)

    words = [wordlist[secure_random_index(len(wordlist))] for _ in range(config.num_words)]
    if config.capitalize:
        words = [word.capitalize() for word in words]

    passphrase = config.separator.join(words)
    if config.include_number:
        passphrase += str(secure_random_index(10))
    if config.include_symbol:
        passphrase += DEFAULT_SPECIAL_CHARS[secure_random_index(len(DEFAULT_SPECIAL_CHARS))]

    min_length = config.num_words + len(config.separator) * (config.num_words - 1)
    if len(passphrase) < min_length:
        raise ValueError("Generated passphrase is shorter than the expected minimum length.")

    return passphrase


def generate_passphrases(config: PassphraseConfig, wordlist: List[str]) -> List[str]:
    """Generates a batch of unique passphrases."""
    results: List[str] = []
    seen = set()
    max_attempts = max(config.count * 15, 100)
    attempts = 0

    while len(results) < config.count and attempts < max_attempts:
        phrase = generate_passphrase(config, wordlist)
        attempts += 1
        if phrase not in seen:
            seen.add(phrase)
            results.append(phrase)

    if len(results) < config.count:
        raise RuntimeError(
            f"Could only generate {len(results)} unique passphrases out of {config.count} "
            f"requested. Consider increasing word count or wordlist size."
        )

    return results
