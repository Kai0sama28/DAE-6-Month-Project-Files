"""
Rubric criterion: Constant Usage in Variables
Define and apply a constant within the code using a descriptive name.

Adapted from: python_1/tracker keeper 2.5.py
  (USERNAME, PASSWORD, DUE_DATE_FILE, DEFAULT work time constants)
"""

# Uppercase, descriptive names signal values that are meant to stay fixed.
MAX_LOGIN_ATTEMPTS = 3
DUE_DATE_FILE = "due_date.txt"
DEFAULT_WORK_MINUTES = 25


def credentials_match(username, password):
    """Check input against the illustrative stored credentials."""
    return username == "rell" and password == "green"


def main():
    print("Tracker Keeper login demo")
    print(f"Maximum login attempts: {MAX_LOGIN_ATTEMPTS}")
    print(f"Due dates are stored in: {DUE_DATE_FILE}")
    print(f"Default work session: {DEFAULT_WORK_MINUTES} minutes")

    # The descriptive constant controls the loop instead of a magic number.
    for attempt in range(1, MAX_LOGIN_ATTEMPTS + 1):
        print(f"\nAttempt {attempt} of {MAX_LOGIN_ATTEMPTS}")
        username = input("Username: ")
        password = input("Password: ")
        if credentials_match(username, password):
            print("Access granted!")
            return
        print("Incorrect credentials.")

    print(f"Account locked after {MAX_LOGIN_ATTEMPTS} failed attempts.")


if __name__ == "__main__":
    main()
