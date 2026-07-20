from cProfile import label
import os
import time 
from datetime import datetime

from timeit import main
from tkinter import *
from tkinter import messagebox

#     def __init__(self, root):
#         self.root = root
#         self.root.title("Tracker Keeper")
#         self.root.geometry("500x500")
#         self.root.resizable(False, False)

def check_login(self):

    username = self.username_entry.get()

    password = self.password_entry.get()

    if username == USERNAME and password == PASSWORD:

        self.status.config(text="Access Granted")
        print("Access Granted")
        self.root.destroy()  # Close the login window
    else:

        self.status.config(text="Incorrect credentials. Please try again.")       
        print("Incorrect credentials. Please try again.")
        self.root.destroy()  # Close the login window

window = Tk()
#window = Tk() # instatiante an instance of a window
window.geometry("500x500") # size of the window
window.title("Tracker Keeper") # title of the window
label = Label(window, text="Welcome To the Anti Procrastination Station!") # title of the window
label.pack()
button = Button(window, text="Login", command=lambda: check_login(self=window)) # button to login
entry_username = Entry(window, show="*") # entry for username
entry_password = Entry(window, show="*") # entry for password
entry_username.pack()
entry_password.pack()
button.pack()

# print("Welcome To the Anti Procrastination Station!")

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

def Work_time():
    work_minutes = int(input("Enter work session duration in minutes (default is 25): ") or 25)
    work_time_seconds = work_minutes * 60
    short_break_minutes = int(input("short break minutes):"))
    short_break_seconds = short_break_minutes * 60
    long_break_minutes = int(input("long break minutes):"))
    long_break_seconds = long_break_minutes * 60

    prompt = "Enter the number of work sessions you want to complete (default is 4): "
    try:
        sessions = int(input("Number of work sessions: "))
    except ValueError:
        sessions = 4  # default number of sessions

    for session in range(1, sessions + 1):
        print(f"\nWork Session {session}")
        countdown(work_time_seconds)
        if session < sessions:
            print("Short Break")
            countdown(short_break_seconds)
        else:
            print("Long Break")
        countdown(long_break_seconds)
    print("Pomodoro Complete!")
def countdown(seconds):
    while seconds > 0:
        minutes = seconds // 60
        remaining_seconds = seconds % 60
        
        print(f"{minutes:02}:{remaining_seconds:02}", end='\r')

        time.sleep(1)
        seconds -= 1

    print('00:00', end='\r')


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
            Work_time()

            
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

window.mainloop() # keeps the window open until the user closes it