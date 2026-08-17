import os
from datetime import datetime

print("Welcome To the Anti Procrastination Station!")

# the username and password are used to identify the user and store their data
USERNAME = "rell"
PASSWORD = "green"

DUE_DATE_FILE = "due_date.txt"

def load_due_date():
    if not os.path.exists(DUE_DATE_FILE):
        return None
    try:
        with open(DUE_DATE_FILE, "r", encoding="utf-8") as f:
            text = f.read().strip()
            if not text:
                return None
            # stored as ISO format
            return datetime.fromisoformat(text)
    except Exception:
        return None


def save_due_date(dt: datetime):
    with open(DUE_DATE_FILE, "w", encoding="utf-8") as f:
        f.write(dt.isoformat())


def prompt_for_datetime():
    prompt = (
        "Enter due date/time in 'YYYY-MM-DD HH:MM:SS' format\n"
        "or ISO format (e.g. 2026-12-31T23:59:59): "
    )
    while True:
        s = input(prompt).strip()
        try:
            # try common format first
            dt = datetime.strptime(s, "%Y-%m-%d %H:%M:%S")
            return dt
        except Exception:
            try:
                dt = datetime.fromisoformat(s)
                return dt
            except Exception:
                print("Invalid format. Try again.")

def time_left(dt: datetime):
    now = datetime.now()
    diff = dt - now
    return diff

def main():
    # simple login loop
    while True:
        input_username = input("Please enter your username: ")
        input_password = input("Please enter your password: ")
        if input_username == USERNAME and input_password == PASSWORD:
            print("Access granted!")
            break
        print("Incorrect credentials. Please try again.")

    print(f"Welcome, {USERNAME}!")

    # main menu: set or view due date
    while True:
        print("\nMenu:\n1) Set due date\n2) View due date\n3) Study\n4) Reset timer\n5) Exit")
        choice = input("Choose an option (1/2/3/4/5): ").strip()
        if choice == "1":
            dt = prompt_for_datetime()
            save_due_date(dt)
            print("Due date saved:", dt)
        elif choice == "2":
            dt = load_due_date()
            if dt is None:
                print("No due date set.")
            else:
                diff = time_left(dt)
                days = diff.days
                secs = diff.seconds
                hours = secs // 3600
                minutes = (secs % 3600) // 60
                print("Your existing due date is:", dt)
                if diff.total_seconds() >= 0:
                    print(f"Time left: {days} days, {hours} hours, {minutes} minutes")
                else:
                    print("The due date has passed.")
        elif choice == "3":
            print("Starting study session...")
            # Add study session logic here
            import time

            WORK_TIME = 25 * 60
            SHORT_BREAK = 5 * 60
            LONG_BREAK = 15 * 60

            sessions = 1


            def countdown(seconds):
                while seconds > 0:
                    minutes = seconds // 60
                    remaining_seconds = seconds % 60
                    print(f"{minutes:02}:{remaining_seconds:02}", end="\r")
                    time.sleep(1)
                    seconds -= 1
                print("00:00")

            for session in range(1, sessions + 1):
                print(f"\nWork Session {session}")
                countdown(WORK_TIME)
                if session < sessions:
                    print("Short Break")
                    countdown(SHORT_BREAK)
                print("Long Break")
                countdown(LONG_BREAK)
            print("Pomodoro Complete!")
        elif choice == "4":
            print("Resetting timer...")
            # Add timer reset logic here
            dt =  prompt_for_datetime()
            save_due_date(dt)
        elif choice == "5":
            print("Goodbye!")
            break
        else:
            print("Invalid option. Please enter 1, 2, 3, 4, or 5.")

if __name__ == "__main__":
    main()


