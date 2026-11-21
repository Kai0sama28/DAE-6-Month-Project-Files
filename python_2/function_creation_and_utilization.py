"""
Rubric criterion: Function Creation and Utilization
Write functions that require one or multiple arguments and include at least one
function that returns a computed value.

Adapted from: python_1/functions.py/functions.py (greet_user(username)) and
python_1/tracker keeper 2.5.py (time_left(dt) returns a computed value)
"""
from datetime import datetime, timedelta


def greet_user(username):
    """One required argument; prints a greeting."""
    print("Hello, " + username + "!")
    print("Hope you have a nice day.")


def time_left(due_date, now):
    """Two required arguments; returns a computed timedelta."""
    return due_date - now


def format_duration(delta):
    """One argument; returns a computed, formatted string."""
    minutes = int(delta.total_seconds() // 60)
    return f"{minutes} minute(s)"


def main():
    name = input("Enter your name: ")
    greet_user(name)

    due_date = datetime.now() + timedelta(minutes=90)
    remaining = time_left(due_date, datetime.now())
    print("Time left:", format_duration(remaining))


if __name__ == "__main__":
    main()
