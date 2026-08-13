import tkinter as tk

# Initialize the main window
root = tk.Tk()
root.title("VS Code Tkinter Test")
root.geometry("300x200")

# Add a simple text label
label = tk.Label(root, text="Tkinter is working!")
label.pack(pady=20)

# CRITICAL: This keeps the window open in VS Code
root.mainloop()
