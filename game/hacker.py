import random
import time
import requests
import hashlib
import json
import os
import platform
import socket
import base64
import binascii
from datetime import datetime
from colorama import init, Fore, Style

# Initialize colorama
init(autoreset=True)

# Global Constants
ATTEMPTS_REMAINING = 3
TIME_LIMIT = 10  # seconds
EMOJIS = {
    "lock": "🔒", "key": "🔑", "computer": "💻", "hourglass": "⏳",
    "hammer": "🔨", "skull": "💀", "world": "🌐", "fire": "🔥",
    "book": "📖", "mag": "🔍", "bomb": "💣", "checkmark": "✔️"
}

CREDENTIALS = {"admin": "password123", "user": "letmein", "guest": "guestpass"}
USER_INFO = {"username": "hacker_pro", "hostname": "target_server"}

def display_intro():
    """Displays the game introduction."""
    print(Fore.MAGENTA + Style.BRIGHT + "Welcome to the Hacker Challenge!")
    print(Fore.YELLOW + f"You have {ATTEMPTS_REMAINING} attempts to hack into the system.")
    print(Fore.YELLOW + f"Each challenge must be solved within {TIME_LIMIT} seconds.")

def generate_math_challenge():
    """Generates a random math challenge."""
    operations = ['+', '-', '*', '/']
    num1, num2 = random.randint(10, 50), random.randint(1, 10)
    operator = random.choice(operations)
    result = eval(f"{num1} {operator} {num2}") if operator != '/' else round(num1 / num2, 2)
    return f"What is {num1} {operator} {num2}?", result

def solve_algorithm_challenge():
    """Solves an algorithmic challenge."""
    numbers = random.sample(range(1, 100), 5)
    target = sum(numbers) // len(numbers)
    print(Fore.CYAN + f"Numbers: {numbers}\nCalculate the average (rounded down).")
    start_time = time.time()
    try:
        answer = int(input(Fore.CYAN + "Your answer: ").strip())
        return answer == target and time.time() - start_time <= TIME_LIMIT
    except ValueError:
        return False

def username_password_challenge():
    """Handles username and password authentication."""
    username = input(Fore.CYAN + "Enter username: ").strip()
    password = input(Fore.CYAN + "Enter password: ").strip()
    return CREDENTIALS.get(username) == password

def log_attempt(success):
    """Logs hacking attempts."""
    log_entry = {"timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                 "username": USER_INFO['username'], "hostname": USER_INFO['hostname'], "success": success}
    with open("hacker_game_log.json", "a") as log_file:
        json.dump(log_entry, log_file)
        log_file.write("\n")

def system_info():
    """Displays system information."""
    command = "ver" if platform.system() == "Windows" else "uname -a"
    os.system(command)

def encrypt_decrypt(text, mode='encrypt'):
    """Encrypts or decrypts text using simple reversal."""
    return text[::-1] if mode == 'encrypt' else text[::-1]

def hacker_shell():
    """Interactive shell with hacking-themed commands."""
    commands = {
        "status": lambda: print(Fore.GREEN + f"Attempts remaining: {ATTEMPTS_REMAINING} {EMOJIS['hourglass']}"),
        "whoami": lambda: print(Fore.GREEN + f"Current user: {USER_INFO['username']}"),
        "hostname": lambda: print(Fore.GREEN + f"Current hostname: {USER_INFO['hostname']}"),
        "system": system_info,
        "encrypt": lambda: print(Fore.GREEN + f"Encrypted: {encrypt_decrypt(input(Fore.CYAN + 'Enter text: '))}"),
        "decrypt": lambda: print(Fore.GREEN + f"Decrypted: {encrypt_decrypt(input(Fore.CYAN + 'Enter text: '), 'decrypt')}"),
        "exit": lambda: exit(print(Fore.MAGENTA + "Exiting shell..."))
    }

    while True:
        command = input(Fore.CYAN + "Shell> ").strip().lower()
        commands.get(command, lambda: print(Fore.RED + "Unknown command."))()

def hacker_game():
    """Main game loop."""
    global ATTEMPTS_REMAINING
    display_intro()

    while ATTEMPTS_REMAINING > 0:
        if username_password_challenge() or solve_algorithm_challenge():
            hacker_shell()
            break
        ATTEMPTS_REMAINING -= 1
        if ATTEMPTS_REMAINING == 0:
            print(Fore.RED + f"Out of attempts. Game over. {EMOJIS['skull']}")
            break

if __name__ == "__main__":
    hacker_game()
