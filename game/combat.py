import random
import time
from colorama import init, Fore, Style

# Initialize colorama
init(autoreset=True)

# Game variables
MAX_HEALTH = 100
player_health = MAX_HEALTH
enemy_health = MAX_HEALTH

# Actions and Emojis
actions = {
    "attack": "⚔️",
    "defend": "🛡️",
    "heal": "💉",
    "run": "🏃‍♂️"
}

def print_colored(text, color):
    print(getattr(Fore, color.upper()) + text)

def player_turn():
    print_colored("Choose your action:", "cyan")
    for i, (action, emoji) in enumerate(actions.items(), 1):
        print_colored(f"{i}. {action.capitalize()} {emoji}", "yellow")

    choice = input(Fore.CYAN + "Your choice: ").strip()
    return list(actions.keys())[int(choice) - 1] if choice in map(str, range(1, 5)) else "attack"

def enemy_turn():
    return random.choices(["attack", "defend", "heal"], [0.6, 0.2, 0.2])[0]

def display_health():
    print_colored(f"Player Health: {player_health} ❤️", "green")
    print_colored(f"Enemy Health: {enemy_health} 💔", "red")

def combat():
    global player_health, enemy_health

    print_colored("Welcome to Combat Game!", "magenta")
    print_colored("Defeat the enemy using your skills. Choose wisely!", "yellow")
    display_health()

    while player_health > 0 and enemy_health > 0:
        player_action = player_turn()
        enemy_action = enemy_turn()

        print_colored(f"You chose: {actions[player_action]}", "cyan")
        print_colored(f"Enemy chose: {actions[enemy_action]}", "red")

        if player_action == "run":
            print_colored("You ran away! Game over.", "yellow")
            return

        if player_action == "attack":
            if enemy_action != "defend":
                damage = random.randint(15, 30)
                enemy_health = max(0, enemy_health - damage)
                print_colored(f"You dealt {damage} damage! 💥", "green")
            else:
                print_colored("Enemy blocked your attack! 🛡️", "red")

        if enemy_action == "attack":
            if player_action != "defend":
                damage = random.randint(10, 25)
                player_health = max(0, player_health - damage)
                print_colored(f"Enemy dealt {damage} damage! 💥", "red")
            else:
                print_colored("You blocked the enemy's attack! 🛡️", "green")

        if player_action == "heal":
            heal = random.randint(10, 20)
            player_health = min(MAX_HEALTH, player_health + heal)
            print_colored(f"You healed for {heal} health! 💉", "green")

        if enemy_action == "heal" and enemy_health < MAX_HEALTH:
            heal = random.randint(5, 15)
            enemy_health = min(MAX_HEALTH, enemy_health + heal)
            print_colored(f"Enemy healed for {heal} health! 💉", "red")

        display_health()
        time.sleep(1)

    print_colored("You were defeated! 💀" if player_health <= 0 else "You defeated the enemy! 🎉", "magenta")
    print_colored("Game over.", "magenta")

if __name__ == "__main__":
    combat()
