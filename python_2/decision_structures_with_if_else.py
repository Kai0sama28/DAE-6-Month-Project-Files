"""
Rubric criterion: Decision Structures with if-else
Construct an if-else statement to direct the flow of execution based on a condition.

Adapted from: python_1/home_destiny_guru.py
  (login check with if/else and the raining / at-home decision table)
"""


def decide_action(raining, at_home):
    """Return a recommendation using if / elif / else branching."""
    if raining and at_home:
        return "Stay home"
    elif raining and not at_home:
        return "Stay at work"
    elif not raining and at_home:
        return "Go to work"
    else:
        return "Go home"


def main():
    username = input("Enter your username: ")
    password = input("Enter your password: ")

    # A straightforward if-else directs the flow of execution.
    if username == "rickc137" and password == "noobnoob":
        print("Access granted! Welcome, " + username + "!")
    else:
        print("Access denied! Incorrect username or password.")

    raining = input("Is it raining? (y/n): ").strip().lower() == "y"
    at_home = input("Are you at home? (y/n): ").strip().lower() == "y"
    print(decide_action(raining, at_home))


if __name__ == "__main__":
    main()
