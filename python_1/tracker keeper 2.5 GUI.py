import os
from datetime import datetime
import tkinter as tk
from tkinter import messagebox, simpledialog

USERNAME = "rell"
PASSWORD = "green"
DUE_DATE_FILE = "due_date.txt"

BASE_DIR = os.path.dirname(os.path.abspath(__file__))


def data_file(name):
    return os.path.join(BASE_DIR, name)


def load_due_date():
    path = data_file(DUE_DATE_FILE)
    if not os.path.exists(path):
        return None
    try:
        with open(path, "r", encoding="utf-8") as f:
            text = f.read().strip()
            return datetime.fromisoformat(text) if text else None
    except Exception:
        return None


def save_due_date(dt):
    with open(data_file(DUE_DATE_FILE), "w", encoding="utf-8") as f:
        f.write(dt.isoformat())


def parse_datetime(s):
    s = s.strip()
    if not s:
        raise ValueError("Empty input")
    try:
        return datetime.strptime(s, "%Y-%m-%d %H:%M:%S")
    except ValueError:
        return datetime.fromisoformat(s)


def describe_remaining(dt):
    now = datetime.now()
    diff = dt - now
    if diff.total_seconds() < 0:
        return "The due date has passed."
    days = diff.days
    hours, rem = divmod(diff.seconds, 3600)
    minutes, seconds = divmod(rem, 60)
    if days > 0:
        return f"{days}d {hours}h {minutes}m {seconds}s"
    if hours > 0:
        return f"{hours}h {minutes}m {seconds}s"
    return f"{minutes}m {seconds}s"


class LoginFrame(tk.Frame):
    def __init__(self, master, on_success):
        super().__init__(master, padx=40, pady=40)
        self.on_success = on_success

        tk.Label(self, text="Tracker Keeper", font=("Arial", 22, "bold")).pack(pady=(0, 4))
        tk.Label(self, text="The Anti Procrastination Station", font=("Arial", 11)).pack(pady=(0, 20))

        tk.Label(self, text="Username:").pack(anchor="w")
        self.username_var = tk.StringVar()
        tk.Entry(self, textvariable=self.username_var, width=28).pack(pady=(2, 10), fill="x")

        tk.Label(self, text="Password:").pack(anchor="w")
        self.password_var = tk.StringVar()
        tk.Entry(self, textvariable=self.password_var, show="*", width=28).pack(pady=(2, 20), fill="x")

        tk.Button(self, text="Login", command=self._login, width=18).pack()
        self.error_var = tk.StringVar()
        tk.Label(self, textvariable=self.error_var, fg="red", font=("Arial", 10)).pack(pady=(10, 0))

        self.username_var.set(USERNAME)
        self.password_var.set(PASSWORD)

    def _login(self):
        if (
            self.username_var.get() == USERNAME
            and self.password_var.get() == PASSWORD
        ):
            self.error_var.set("")
            self.on_success()
        else:
            self.error_var.set("Incorrect credentials. Please try again.")


class MainFrame(tk.Frame):
    def __init__(self, master):
        super().__init__(master, padx=30, pady=30)
        self._pomodoro = None

        tk.Label(self, text=f"Welcome, {USERNAME}!", font=("Arial", 16, "bold")).pack(pady=(0, 6))

        self.due_var = tk.StringVar()
        self.due_label = tk.Label(self, textvariable=self.due_var, font=("Consolas", 18, "bold"), fg="#1a5276")
        self.due_label.pack(pady=10)

        btn = tk.Button
        btn(self, text="Set Due Date", command=self._set_due_date, width=24).pack(pady=4)
        btn(self, text="Reset Timer", command=self._reset_timer, width=24).pack(pady=4)
        btn(self, text="Study (Pomodoro)", command=self._open_pomodoro, width=24).pack(pady=4)
        btn(self, text="Exit", command=self.master.destroy, width=24).pack(pady=4)

        self._refresh_due()

    def _refresh_due(self):
        dt = load_due_date()
        if dt is None:
            self.due_var.set("No due date set yet.")
            self.due_label.config(fg="gray")
        else:
            self.due_label.config(fg="#1a5276" if (dt - datetime.now()).total_seconds() >= 0 else "#c0392b")
            self.due_var.set(describe_remaining(dt))
        self.after(1000, self._refresh_due)

    def _prompt_datetime(self):
        answer = simpledialog.askstring(
            "Due Date / Time",
            "Enter due date/time in 'YYYY-MM-DD HH:MM:SS' format\n"
            "or ISO format (e.g. 2026-12-31T23:59:59):",
            parent=self,
        )
        if answer is None:
            return None
        try:
            return parse_datetime(answer)
        except (ValueError, TypeError):
            messagebox.showerror("Invalid Input", "That format is not recognized. Please try again.", parent=self)
            return None

    def _set_due_date(self):
        dt = self._prompt_datetime()
        if dt is not None:
            save_due_date(dt)
            self._refresh_due()
            messagebox.showinfo("Saved", f"Due date saved: {dt}", parent=self)

    def _reset_timer(self):
        self._set_due_date()

    def _open_pomodoro(self):
        if self._pomodoro is not None and self._pomodoro.winfo_exists():
            self._pomodoro.lift()
            return
        self._pomodoro = PomodoroWindow(self)


class PomodoroWindow(tk.Toplevel):
    FONT = ("Consolas", 44, "bold")

    def __init__(self, master):
        super().__init__(master)
        self.title("Study - Pomodoro")
        self.geometry("360x360")
        self.resizable(False, False)
        self.transient(master)
        self.grab_set()

        self._after_id = None
        self._running = False
        self._remaining = 0
        self._session = 0
        self._sessions_total = 0
        self._phase = "idle"

        body = tk.Frame(self, padx=20, pady=16)
        body.pack(fill="both", expand=True)

        self.work_var = tk.StringVar(value="25")
        self.short_var = tk.StringVar(value="5")
        self.long_var = tk.StringVar(value="15")
        self.sessions_var = tk.StringVar(value="4")

        self._field(body, "Work minutes:", self.work_var, 0)
        self._field(body, "Short break minutes:", self.short_var, 1)
        self._field(body, "Long break minutes:", self.long_var, 2)
        self._field(body, "Number of sessions:", self.sessions_var, 3)

        self.status_var = tk.StringVar(value="Ready")
        tk.Label(body, textvariable=self.status_var, font=("Arial", 11, "bold")).pack(pady=(10, 0))

        self.time_var = tk.StringVar(value="00:00")
        tk.Label(body, textvariable=self.time_var, font=self.FONT, fg="#2471a3").pack()

        controls = tk.Frame(body)
        controls.pack(pady=8)
        self.start_btn = tk.Button(controls, text="Start", command=self.start, width=8)
        self.start_btn.pack(side="left", padx=4)
        self.stop_btn = tk.Button(controls, text="Stop", command=self.stop, state="disabled", width=8)
        self.stop_btn.pack(side="left", padx=4)
        tk.Button(controls, text="Close", command=self.destroy, width=8).pack(side="left", padx=4)

        self.protocol("WM_DELETE_WINDOW", self._on_close)

    def _field(self, parent, label, variable, row):
        tk.Label(parent, text=label).grid(row=row, column=0, sticky="w", pady=3)
        tk.Entry(parent, textvariable=variable, width=8, justify="center").grid(row=row, column=1, padx=10)

    def _read_int(self, var, default, minimum=1):
        try:
            value = int(var.get())
            return max(minimum, value)
        except (ValueError, TypeError):
            return default

    def start(self):
        self._work_sec = self._read_int(self.work_var, 25) * 60
        self._short_sec = self._read_int(self.short_var, 5) * 60
        self._long_sec = self._read_int(self.long_var, 15) * 60
        self._sessions_total = self._read_int(self.sessions_var, 4)

        self._session = 0
        self._running = True
        self.start_btn.config(state="disabled")
        self.stop_btn.config(state="normal")
        self._next_phase()

    def stop(self):
        if self._after_id is not None:
            self.after_cancel(self._after_id)
            self._after_id = None
        self._running = False
        self._phase = "idle"
        self.status_var.set("Stopped")
        self.time_var.set("00:00")
        self.start_btn.config(state="normal")
        self.stop_btn.config(state="disabled")

    def _next_phase(self):
        if not self._running:
            return
        self._session += 1
        if self._session > self._sessions_total:
            self._complete()
            return
        self._phase = "work"
        self._remaining = self._work_sec
        self.status_var.set(f"Work Session {self._session}/{self._sessions_total}")
        self._start_ticking()

    def _tick(self):
        if not self._running:
            return
        if self._remaining <= 0:
            self._phase_finished()
            return
        self.time_var.set(f"{self._remaining // 60:02d}:{self._remaining % 60:02d}")
        self._remaining -= 1
        self._after_id = self.after(1000, self._tick)

    def _phase_finished(self):
        if self._phase == "work":
            if self._session < self._sessions_total:
                self._phase = "short"
                self._remaining = self._short_sec
                self.status_var.set(f"Short Break (after session {self._session})")
            else:
                self._phase = "long"
                self._remaining = self._long_sec
                self.status_var.set("Long Break - well done!")
        else:
            # break ended -> start next work session (long break finishes the run)
            if self._phase == "long":
                self._complete()
                return
            self._next_phase()
            return
        self._start_ticking()

    def _start_ticking(self):
        if not self._running:
            return
        self._after_id = self.after(1000, self._tick)

    def _complete(self):
        self._running = False
        self.status_var.set("Pomodoro Complete!")
        self.time_var.set("00:00")
        self.start_btn.config(state="normal")
        self.stop_btn.config(state="disabled")
        messagebox.showinfo("Pomodoro", "All sessions complete. Great work!", parent=self)

    def _on_close(self):
        self.stop()
        self.destroy()


def main():
    root = tk.Tk()
    root.title("Tracker Keeper - Anti Procrastination Station")
    root.geometry("460x420")
    root.resizable(False, False)

    def show_main():
        for child in root.winfo_children():
            child.destroy()
        MainFrame(root).pack(fill="both", expand=True)

    LoginFrame(root, on_success=show_main).pack(fill="both", expand=True)
    root.mainloop()


if __name__ == "__main__":
    main()