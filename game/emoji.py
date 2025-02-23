import random
import time
from colorama import init, Fore, Style

# Initialize colorama
init(autoreset=True)

# Lists of emojis, words, and hints by level
levels = {
    1: {
        'emojis': ['🍎', '🍌', '🍇', '🍉', '🍓', '🍊', '🍒', '🍍', '🥭', '🍑'],
        'words': ['APPLE', 'BANANA', 'GRAPE', 'WATERMELON', 'STRAWBERRY', 'ORANGE', 'CHERRY', 'PINEAPPLE', 'MANGO', 'PEACH'],
        'hints': ['A red fruit', 'A yellow curved fruit', 'A bunch of small fruits', 'A juicy summer fruit', 'A small red fruit', 'A citrus fruit', 'A small red stone fruit', 'A tropical fruit with spiky skin', 'A tropical fruit with a pit', 'A fuzzy-skinned fruit']
    },
    2: {
        'emojis': ['🍕', '🍔', '🍟', '🌭', '🍿', '🍣', '🍜', '🥗', '🍝', '🌮', '☕', '🍵', '🥛', '🧃', '🍺', '🍷', '🍸', '🥤', '🧋', '🥃'],
        'words': ['PIZZA', 'BURGER', 'FRIES', 'HOTDOG', 'POPCORN', 'SUSHI', 'NOODLES', 'SALAD', 'PASTA', 'TACO', 'COFFEE', 'TEA', 'MILK', 'JUICE', 'BEER', 'WINE', 'COCKTAIL', 'SODA', 'BUBBLE TEA', 'WHISKEY'],
        'hints': ['An Italian dish', 'A round sandwich', 'Fried potatoes', 'A sandwich with a sausage', 'A cinema snack', 'Japanese rice and fish dish', 'An Asian noodle dish', 'A mix of vegetables', 'An Italian noodle dish', 'A Mexican dish', 'Morning beverage', 'Afternoon beverage', 'Dairy drink', 'Fruit drink', 'Alcoholic beverage', 'Made from grapes', 'Mixed drink', 'Carbonated drink', 'Popular drink with tapioca', 'Strong alcoholic drink']
    },
    3: {
        'emojis': ['🚗', '✈️', '🚀', '🛳️', '🚂', '🚲', '🛴', '🚁', '🏰', '🏠', '🏢', '🏥', '🏫', '🏟️', '⚽', '🐶', '🐱', '🦁', '🐯', '🦊', '🐻', '🐼', '🦉', '🦅', '🇺🇸', '🇨🇦', '🇬🇧', '🇫🇷', '🇧🇷', '🏞️', '🌲', '🌻', '🌼', '🌵', '🍂', '🌊'],
        'words': ['CAR', 'PLANE', 'ROCKET', 'SHIP', 'TRAIN', 'BICYCLE', 'SCOOTER', 'HELICOPTER', 'CASTLE', 'HOUSE', 'OFFICE', 'HOSPITAL', 'SCHOOL', 'STADIUM', 'SOCCER', 'DOG', 'CAT', 'LION', 'TIGER', 'FOX', 'BEAR', 'PANDA', 'OWL', 'EAGLE', 'USA', 'CANADA', 'UK', 'FRANCE', 'BRAZIL', 'PARK', 'PINE', 'SUNFLOWER', 'DAISY', 'CACTUS', 'LEAF', 'WAVE'],
        'hints': ['A four-wheeled vehicle', 'An air transport', 'A space vehicle', 'A sea transport', 'A railway vehicle', 'A two-wheeled vehicle', 'A small motorized vehicle', 'A rotary-wing aircraft', 'Medieval building', 'Home', 'Workplace', 'Medical facility', 'Educational institution', 'Sports venue', 'Popular worldwide sport', 'Man\'s best friend', 'Likes to purr', 'King of the jungle', 'Big striped cat', 'Sly animal', 'Lives in the forest', 'Black and white bear', 'Night bird', 'Bird of prey', 'Stars and stripes', 'Maple leaf', 'Union Jack', 'Eiffel Tower', 'Carnival country', 'Nature area', 'Coniferous tree', 'Yellow flower', 'White flower', 'Desert plant', 'Fallen foliage', 'Ocean movement']
    }
}

# Function to choose a level
def choose_level():
    print(Fore.CYAN + Style.BRIGHT + "Choose a difficulty level (1, 2, or 3) or type 'exit' to quit:")
    level = input(Fore.YELLOW + "Level: ").strip().lower()
    
    if level == 'exit':
        return None
    
    while not level.isdigit() or int(level) not in levels:
        print(Fore.RED + "Invalid level. Please choose between 1, 2, and 3, or type 'exit' to quit.")
        level = input(Fore.YELLOW + "Level: ").strip().lower()
        if level == 'exit':
            return None
    
    return int(level)

# Function to play the game
def play_game(level):
    # Select a random word and emoji
    index = random.randint(0, len(levels[level]['words']) - 1)
    word_to_guess = levels[level]['words'][index]
    emoji_to_guess = levels[level]['emojis'][index]
    hint = levels[level]['hints'][index]
    
    # Game loop
    print(Fore.CYAN + Style.BRIGHT + f"Guess the word associated with this emoji: {emoji_to_guess}")
    print(Fore.MAGENTA + f"Hint: {hint}")
    
    attempt = ""
    num_attempts = 0
    start_time = time.time()
    
    while attempt.upper() != word_to_guess:
        attempt = input(Fore.YELLOW + "Your answer: ")
        if attempt.lower() == 'exit':
            return None, None
        
        num_attempts += 1
        
        if attempt.upper() == word_to_guess:
            elapsed_time = time.time() - start_time
            print(Fore.GREEN + f"Congratulations! You guessed the word in {elapsed_time:.2f} seconds!")
        else:
            print(Fore.RED + "No, try again.")
    
    return num_attempts, elapsed_time

# Function to ask the player if they want to continue
def continue_playing():
    response = input(Fore.CYAN + Style.BRIGHT + "Do you want to play again? (yes/no): ").strip().lower()
    return response == 'yes'

# Main game flow
def main():
    total_attempts = 0
    total_time = 0
    games_played = 0
    
    while True:
        level = choose_level()
        if level is None:
            break
        
        attempts, elapsed_time = play_game(level)
        if attempts is None:
            break
        
        total_attempts += attempts
        total_time += elapsed_time
        games_played += 1
        
        if not continue_playing():
            break
    
    print(Fore.MAGENTA + Style.BRIGHT + f"Thanks for playing! You played {games_played} games.")
    print(Fore.MAGENTA + f"Total attempts: {total_attempts}, Total time: {total_time:.2f} seconds.")
    
    if games_played > 0:
        print(Fore.MAGENTA + f"Average attempts per game: {total_attempts / games_played:.2f}, Average time per game: {total_time / games_played:.2f} seconds.")

# Run the game
if __name__ == "__main__":
    main()
