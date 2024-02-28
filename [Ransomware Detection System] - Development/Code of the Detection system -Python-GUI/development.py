import tkinter as tk # Tkinter is used to make the GUI
import tkinter.filedialog # This is used to open file dialogs
from tkinter.ttk import * # this line imports all the classes and functions from the module
import os #this helps to interact with the OS
import time # This helps workign with time such as measuring time intervals
import yara # This module is a pattern matching tool used to identify and classify based on patterns and rules
import io # This helps to work with streams and input/output oerations
import sys # This is used to interact strongly with the interpreter or system

# Get the path of the executable
exe_path = os.path.abspath(sys.argv[0])

# Open the executable as a binary file
with open(exe_path, 'rb') as exe_file:
    
    # Load the executable as a byte stream
    exe_data = io.BytesIO(exe_file.read())
    
# Create the root window
root = tk.Tk()
root.geometry("1000x700") 
root.title("Ransomware Detection system")
root.configure(bg="#2C2F33")

# Create a label to prompt the user to select a file
label = tk.Label(root, text="CHOOSE A FILE TO SCAN FOR ANY RANSOMWARE DETECTION", font=("Arial", 23), bg="#2C2F33", fg="#FFFFFF")
label.pack(pady=(50,20))

# Define a function to open a file selection dialog and display file metadata
def open_file():
    # Open the file selection dialog
    root.filename = tk.filedialog.askopenfilename(initialdir="This PC",
                                                   title="SELECT A FILE",
                                                   filetypes=(("all files","*"),
                                                              ("docx files",".docx"),
                                                              ("png files",".png"),
                                                              ("jpg files",".jpg"),
                                                              ("pptx files",".pptx"),
                                                              ("exe files",".exe"),
                                                              ("dll files", ".dll"),
                                                              ("bin files", ".bin"),
                                                              ("pdf files", ".pdf"),
                                                              ("mkv files", ".mkv"),
                                                              ("txt files", ".txt")))
    # Display the file's name
    root_label1 = tk.Label(root, text=root.filename, font=("Arial", 16), bg="#2C2F33", fg="#FFFFFF")
    root_label1.pack()

    # Get the file's metadata
    file_status = os.stat(root.filename)
    size = int(file_status.st_size/(1024*1024))
    mod_time = time.ctime(os.path.getmtime(root.filename))
    creat_time = time.ctime(os.path.getctime(root.filename))
    access_time = time.ctime(os.path.getatime(root.filename))

    # Display the file metadata
    file_info = tk.Label(root, text="FILE DESCRIPTION", font=("TImes New Roman", 23), bg="#2C2F33", fg="#FFFFFF").pack()
    file_des_label = tk.Label(root, text="The file was Created on: "+str(creat_time), bg="#2C2F33", fg="#FFFFFF").pack()
    file_des_label2 = tk.Label(root, text="The file was last modified on: "+str(mod_time), bg="#2C2F33", fg="#FFFFFF").pack()
    file_des_label3 = tk.Label(root, text ="The file was Accessed on: "+str(access_time), bg="#2C2F33", fg="#FFFFFF").pack()
    if size == 0:
        size = file_status.st_size
        label2 = tk.Label(root, text ="File Size in Bytes: "+str(size), bg="#2C2F33", fg="#FFFFFF").pack()
    else:
        label2 = tk.Label(root, text ="File Size in MegaBytes: "+str(size), bg="#2C2F33", fg="#FFFFFF").pack()

# Define a function to return the file name
def get_file():
    return root.filename
# Define a function to scan the file for ransomware
def scan_file():
    # Display a label to show that the scan is in progress
    label3 = tk.Label(root, text="Result", font =("Display", 20), bg="#2C2F33", fg="#FFFFFF").pack()

    # Create a progress bar
    pb1 = tkinter.ttk.Progressbar(root, orient=tk.HORIZONTAL, length=900, mode='determinate')
    pb1.pack(expand=True)

    # Update the progress bar and sleep for 1 second 3 times
    for i in range(3):
        root.update_idletasks()
        pb1['value'] += 50
        time.sleep(1)
        
    # Compile the YARA rules from the source
    rules = yara.compile(filepath = r"C:\Users\Lenovo\Documents\FYPprep\YaraCode\rules.yar")
    # Open the file and scan it for ransomware
    file = get_file()
    with open(file, 'rb') as f:
        matches = rules.match(data=f.read(), externals={})

    # Check if any matches were found
    if len(matches) > 0:
        # Display a message indicating that the file is infected
        label7 = tk.Label(root, text="Completed", font = ("Display",20), bg="#2C2F33", fg="#FFFFFF")
        label7.pack()
        label8 = tk.Label(root, text="The file is infected with ransomware!", font=("Display", 20), bg="#2C2F33", fg="#800000")
        label8.pack()
        #deleting the file
        def delete_file():
            file_path = root.filename
            if os.path.isfile(file_path):
                os.remove(file_path)
                label11=tk.Button(root,text="File has been deleted successfully.", font=("Display", 20), bg="#2C2F33", fg="#990000")
                label11.pack()
            else:
                label12=tk.Button(root,text="File does not exist.", font=("Display", 20),  bg="#2C2F33", fg="000066")
                label12.pack()
        # Create the "Scan" button and "Delete Button"
        delete_button = tk.Button(root, text="Delete The File", command=delete_file)
        delete_button.pack()
        exit_button = tk.Button(root, text="Exit", command=exit)
        exit_button.pack()
    else:
        # Display a message indicating that the file is not infected
        label9 = tk.Label(root, text="Completed", font = ("Display",20),  bg="#2C2F33", fg="#9999FF")
        label9.pack()
        label10 = tk.Label(root, text="The file is not infected with ransomware.", font=("Display", 20), bg="#2C2F33", fg="#006633")
        label10.pack()

# Create the "Open" button
open_button = tk.Button(root, text="Open", command=open_file)
open_button.pack()

# Create the "Scan" button
scan_button = tk.Button(root, text="Scan", command=scan_file)
scan_button.pack()

# Run the Tkinter event loop
root.mainloop()

