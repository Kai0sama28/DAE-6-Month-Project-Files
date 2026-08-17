#import tkinter as tk
from tkinter import *
# windows = serves as a container to hold or contain these widgets
# widgets = GUI elements: buttons, text boxes, labels, images etc.  

window = Tk() #instantiate an instance of a window 
window.geometry("400x200") #set the size of the window
window.title("My First GUI") #set the title of the window

window.mainloop() #place window on computer screen, listen for events. 



# # 1. Create the main application window
# root = tk.Tk()
# root.title("My First GUI")
# root.geometry("400x200")

# # 2. Create a widget (a simple text label)
# label = tk.Label(root, text="Hello, Tkinter!", font=("Arial", 16))

# # 3. Position the widget inside the window
# label.pack(pady=20)

# # 4. Start the application event loop
# root.mainloop()
