"""
Rubric criterion: Repetition with while Loops
Use a while loop to execute code repeatedly based on a boolean condition.

Adapted from: python_1/home_destiny_guru.py (retry loop) and
python_1/tracker keeper 2.5.py (countdown() while loop)
"""

COUNTDOWN_START = 3


def countdown(seconds):
    """Repeat while the boolean condition seconds > 0 is true."""
    while seconds > 0:
        print(f"{seconds:02}:00", end="\r")
        seconds -= 1
    print("00:00")


def main():
    # This while loop repeats until the boolean flag becomes False.
    keep_going = True
    attempts = 0
    while keep_going:
        answer = input("Type 'y' to keep looping or 'n' to stop: ").strip().lower()
        attempts += 1
        if answer == "n":
            keep_going = False
        elif answer != "y":
            print("Please enter only 'y' or 'n'.")

    print(f"Loop finished after {attempts} attempt(s).")
    countdown(COUNTDOWN_START)


if __name__ == "__main__":
    main()
