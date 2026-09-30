Tracker Keeper - Run Instructions

This project uses Tkinter; macOS system Python may link against an older Tcl/Tk that crashes on new macOS versions.

Recommended (confirmed working): use Homebrew Python with Homebrew Tcl/Tk.

Install (if needed):

```bash
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"  # if Homebrew missing
brew install tcl-tk python@3.11 python-tk@3.11
```

Run the GUI with the Homebrew Python executable:

```bash
/opt/homebrew/bin/python3.11 "tracker keeper 2.5 GUI.py"
```

Optional: add Homebrew Python to your `PATH` (add to `~/.zshrc` or `~/.bash_profile`):

```bash
export PATH="/opt/homebrew/opt/python@3.11/libexec/bin:/opt/homebrew/bin:$PATH"
```

Notes:
- If you still see a macOS/Tcl-Tk version error, reinstall `python-tk@3.11` or run `brew reinstall tcl-tk`.
- I verified `/opt/homebrew/bin/python3.11` can import `tkinter` and create a `Tk()` root on this machine.
