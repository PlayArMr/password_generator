"""
main.py - Interactive Command-Line Interface for Password & Passphrase Generator.

Provides interactive terminal menus, argparse CLI flag execution,
graceful error/signal handling, and a zero-retention security policy.
"""

import argparse
import sys
from typing import List, Optional, Tuple

from generator import (
    PasswordConfig,
    PassphraseConfig,
    generate_passwords,
    generate_passphrases,
    load_wordlist,
    validate_password_config,
)


def prompt_str(prompt_text: str, default: str) -> str:
    """Prompts the user for a string with a default fallback."""
    response = input(f"{prompt_text} [{default}]: ").strip()
    return response if response else default


def prompt_int(prompt_text: str, default: int, min_val: int = 1) -> int:
    """Prompts the user for an integer >= min_val with a default fallback."""
    while True:
        raw = input(f"{prompt_text} [{default}]: ").strip()
        if not raw:
            return default
        try:
            val = int(raw)
            if val < min_val:
                print(f"  [!] Value must be at least {min_val}. Please try again.")
                continue
            return val
        except ValueError:
            print("  [!] Invalid input. Please enter an integer.")


def prompt_bool(prompt_text: str, default: bool) -> bool:
    """Prompts the user for a yes/no boolean with a default fallback."""
    default_str = "Y/n" if default else "y/N"
    while True:
        raw = input(f"{prompt_text} ({default_str}): ").strip().lower()
        if not raw:
            return default
        if raw in ("y", "yes", "true", "1"):
            return True
        if raw in ("n", "no", "false", "0"):
            return False
        print("  [!] Please enter 'y' or 'n'.")


def display_passwords(items: List[str], item_type: str = "Password") -> None:
    """Displays generated passwords or passphrases with clear formatting."""
    count = len(items)
    print("\n" + "=" * 50)
    print(f"  {item_type.upper()}{'S' if count > 1 else ''} GENERATED ({count})")
    print("=" * 50)
    for i, item in enumerate(items, 1):
        if count > 1:
            print(f"  [{i}] {item}")
        else:
            print(f"  {item}")
    print("-" * 50)
    print("  [Security Note: Passwords are NOT saved or logged.]")
    print("=" * 50 + "\n")


def get_menu_choice() -> str:
    """Displays the interactive main menu and captures a valid option."""
    print("========================================")
    print("    CS50x Secure Password Generator     ")
    print("========================================")
    print("  1. Generate Password")
    print("  2. Generate Passphrase")
    print("  3. Change Settings")
    print("  4. Exit")
    print("----------------------------------------")

    while True:
        choice = input("Enter choice (1-4): ").strip()
        if choice in ("1", "2", "3", "4"):
            return choice
        print("  [!] Invalid selection. Please enter 1, 2, 3, or 4.")


def get_password_settings(current: PasswordConfig) -> PasswordConfig:
    """Interactively prompts user to adjust password settings."""
    print("\n--- Password Settings ---")
    length = prompt_int("Password length", current.length, min_val=1)
    inc_upper = prompt_bool("Include uppercase letters (A-Z)", current.include_uppercase)
    inc_lower = prompt_bool("Include lowercase letters (a-z)", current.include_lowercase)
    inc_digits = prompt_bool("Include digits (0-9)", current.include_digits)
    inc_special = prompt_bool("Include special symbols (!@#$...)", current.include_special)
    exc_ambig = prompt_bool("Exclude ambiguous characters (0, O, 1, l, I, |)", current.exclude_ambiguous)
    count = prompt_int("Number of passwords to generate", current.count, min_val=1)

    new_config = PasswordConfig(
        length=length,
        include_uppercase=inc_upper,
        include_lowercase=inc_lower,
        include_digits=inc_digits,
        include_special=inc_special,
        exclude_ambiguous=exc_ambig,
        count=count,
    )

    try:
        validate_password_config(new_config)
    except ValueError as e:
        print(f"\n[Warning] Selected configuration may be invalid: {e}")

    return new_config


def get_passphrase_settings(current: PassphraseConfig) -> PassphraseConfig:
    """Interactively prompts user to adjust passphrase settings."""
    print("\n--- Passphrase Settings ---")
    num_words = prompt_int("Number of words", current.num_words, min_val=1)
    separator = prompt_str("Word separator character", current.separator)
    capitalize = prompt_bool("Capitalize words", current.capitalize)
    inc_num = prompt_bool("Append numeric suffix", current.include_number)
    inc_sym = prompt_bool("Append symbol suffix", current.include_symbol)
    count = prompt_int("Number of passphrases to generate", current.count, min_val=1)

    return PassphraseConfig(
        num_words=num_words,
        separator=separator,
        capitalize=capitalize,
        include_number=inc_num,
        include_symbol=inc_sym,
        wordlist_path=current.wordlist_path,
        count=count,
    )


def configure_settings(
    pwd_config: PasswordConfig, pass_config: PassphraseConfig
) -> Tuple[PasswordConfig, PassphraseConfig]:
    """Displays settings submenu to modify password or passphrase configuration."""
    print("\n--- Change Settings ---")
    print("  1. Configure Password Options")
    print("  2. Configure Passphrase Options")
    print("  3. Return to Main Menu")
    choice = input("Enter choice (1-3): ").strip()

    if choice == "1":
        pwd_config = get_password_settings(pwd_config)
        print("  [*] Password settings updated.")
    elif choice == "2":
        pass_config = get_passphrase_settings(pass_config)
        print("  [*] Passphrase settings updated.")
    elif choice == "3":
        pass
    else:
        print("  [!] Invalid choice. Returning to main menu.")

    return pwd_config, pass_config


def handle_generate_password(config: PasswordConfig) -> bool:
    """Generates and displays passwords. Returns True on success, False on error."""
    try:
        passwords = generate_passwords(config)
    except (ValueError, RuntimeError) as e:
        print(f"\n[Error] Could not generate password: {e}")
        return False
    display_passwords(passwords, item_type="Password")
    return True


def handle_generate_passphrase(config: PassphraseConfig, wordlist: List[str]) -> bool:
    """Generates and displays passphrases. Returns True on success, False on error."""
    try:
        passphrases = generate_passphrases(config, wordlist)
    except (ValueError, RuntimeError) as e:
        print(f"\n[Error] Could not generate passphrase: {e}")
        return False
    display_passwords(passphrases, item_type="Passphrase")
    return True


def build_arg_parser() -> argparse.ArgumentParser:
    """Builds and returns command-line argument parser."""
    parser = argparse.ArgumentParser(
        description="CS50x Secure Password & Passphrase Generator",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "--mode",
        choices=["interactive", "password", "passphrase"],
        default="interactive",
        help="Execution mode (interactive launches the menu)",
    )
    parser.add_argument("--length", type=int, default=16, help="Password length")
    parser.add_argument("--no-upper", action="store_true", help="Exclude uppercase letters")
    parser.add_argument("--no-lower", action="store_true", help="Exclude lowercase letters")
    parser.add_argument("--no-digits", action="store_true", help="Exclude digits")
    parser.add_argument("--no-special", action="store_true", help="Exclude special characters")
    parser.add_argument(
        "--allow-ambiguous",
        action="store_true",
        help="Include visually ambiguous characters (0, O, 1, l, etc.)",
    )
    parser.add_argument("--words", type=int, default=4, help="Number of passphrase words")
    parser.add_argument("--separator", type=str, default="-", help="Passphrase word separator")
    parser.add_argument("--capitalize", action="store_true", help="Capitalize passphrase words")
    parser.add_argument("--add-number", action="store_true", help="Append random digit to passphrase")
    parser.add_argument("--add-symbol", action="store_true", help="Append random symbol to passphrase")
    parser.add_argument(
        "--wordlist",
        type=str,
        default="wordlist.txt",
        help="Path to custom wordlist file",
    )
    parser.add_argument("-n", "--count", type=int, default=1, help="Number of items to generate")
    return parser


def run_cli_args(args: argparse.Namespace, wordlist: List[str]) -> int:
    """Executes non-interactive password or passphrase generation from CLI flags."""
    if args.mode == "password":
        config = PasswordConfig(
            length=args.length,
            include_uppercase=not args.no_upper,
            include_lowercase=not args.no_lower,
            include_digits=not args.no_digits,
            include_special=not args.no_special,
            exclude_ambiguous=not args.allow_ambiguous,
            count=args.count,
        )
        return 0 if handle_generate_password(config) else 1

    if args.mode == "passphrase":
        config = PassphraseConfig(
            num_words=args.words,
            separator=args.separator,
            capitalize=args.capitalize,
            include_number=args.add_number,
            include_symbol=args.add_symbol,
            wordlist_path=args.wordlist,
            count=args.count,
        )
        return 0 if handle_generate_passphrase(config, wordlist) else 1

    return 0


def interactive_loop(
    pwd_config: PasswordConfig, pass_config: PassphraseConfig, wordlist: List[str]
) -> None:
    """Runs the main interactive menu loop."""
    print("Welcome to CS50x Secure CLI Password Generator!\n")
    while True:
        try:
            choice = get_menu_choice()
            if choice == "1":
                handle_generate_password(pwd_config)
            elif choice == "2":
                handle_generate_passphrase(pass_config, wordlist)
            elif choice == "3":
                pwd_config, pass_config = configure_settings(pwd_config, pass_config)
            elif choice == "4":
                print("\nThank you for using CS50x Password Generator. Goodbye!")
                break
        except (KeyboardInterrupt, EOFError):
            print("\n\nOperation cancelled. Exiting cleanly.")
            break


def main(argv: Optional[List[str]] = None) -> int:
    """Main program entry point."""
    parser = build_arg_parser()
    args = parser.parse_args(argv)

    try:
        wordlist = load_wordlist(args.wordlist)
    except Exception as e:
        print(f"[Warning] Could not load wordlist '{args.wordlist}': {e}")
        wordlist = []

    if args.mode in ("password", "passphrase"):
        return run_cli_args(args, wordlist)

    pwd_config = PasswordConfig()
    pass_config = PassphraseConfig(wordlist_path=args.wordlist)
    interactive_loop(pwd_config, pass_config, wordlist)
    return 0


if __name__ == "__main__":
    sys.exit(main())
