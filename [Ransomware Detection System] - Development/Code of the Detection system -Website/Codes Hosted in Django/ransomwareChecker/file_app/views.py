import ctypes # this helps to create and manipulate C data types
from django.shortcuts import render # This is used to render a Django template with context
from django.views.decorators.csrf import csrf_exempt # This is usex to exempt a view function from the CSRF protection middleware
import os #this helps to interact with the OS
import time # This helps workign with time such as measuring time intervals
import yara # This module is a pattern matching tool used to identify and classify based on patterns and rules
import sys  # This is used to interact strongly with the interpreter or system

# this defines a view function that takes a request and is exempt from the CSRF protection middleware
@csrf_exempt
def Solution(request):
    # this initialize the variables that will be used within the function
    file_path = None
    file_size = None
    file_size1 = None
    mod_time = None
    creat_time = None
    access_time = None
    ransomware_alert = None
    file_deleted = False
    permission_error = None
    name = None
    # this checks if the 'request' method is post
    if request.method == 'POST':
        # Get the uploaded file and its path
        uploaded_file = request.FILES['file']
        file_name = uploaded_file.name
        
    # if the file exists followign functions are carried out

        # Search for the file in the entire system
        for root, dirs, files in os.walk("C:\\"):
            if file_name in files:
                # this helps to get the full file path
                file_path = os.path.join(root, file_name)

                # Get the file's metadata and storing it
                try:
                    file_status = os.stat(file_path)
                    file_size = int(file_status.st_size/(1024*1024))
                    mod_time = time.ctime(os.path.getmtime(file_path))
                    creat_time = time.ctime(os.path.getctime(file_path))
                    access_time = time.ctime(os.path.getatime(file_path))
                    file_size1 = file_status.st_size
                    
                    # print the file's metadata obtained 
                    print("File path:"+file_path)
                    print("File modified time:"+mod_time)
                    print("File created time:"+creat_time)
                    print("File access time:"+access_time)
                    if file_size == 0:
                        print("The File size in MB: "+str(file_size1)+"MB")
                    else:
                        print("The File size in bytes: "+str(file_size)+"Bytes")
                    # Compile the Yara rule
                    rules = yara.compile(filepath = r"C:\Users\Lenovo\Documents\FYPprep\YaraCode\rules.yar")
                    # storing the file path in another variable
                    file = file_path
                    
                    with open(file, 'rb') as f: # this opens the specific file, creates a file object 'f' and properly closes after the code after execution
                        matches = rules.match(data=f.read(), externals={}) # this reads the content of the file object 'f' and passes it to match the rules object
                    if len(matches) > 0: # this line checks if at least one rule matches and the length of the list is greater than 0
                        ransomware_alert = True # if it matches then the variable 'True' indicates the file may contain ransomware
                        # Print the type of ransomware detected from the 'matches' list
                        for match in matches: 
                            print(f"Detected ransomware type: {match.rule}")
                            name = match.rule
                        print("ALERT! The file is infected with Ransomware.")
                        print(file_path) # printing the file path
                        f.close() # closing the file object 'f'
                        if os.path.isfile(file_path): # this checks if the 'file path' exists or not
                            with open(file_path, 'w') as f: # if the file path exists then it opens the files the file in write mode
                                f.write('') # it overwirtes the contents with empty string
                                f.close() # it closes the file object
                            print("The content of the file affected by ransomware has been successfully deleted.")
                            file_deleted = True # if the file is overwriten then it sets the variable to 'True'
                        else:
                            file_deleted = False # if the file is not overwritten then it sets the varibale to 'False'

                    else:
                        ransomware_alert = False # if no match is found then it sets the variable to 'False' indicating that there is no presence of ransomware
                        print("The file is not affected by Ransomware.")
                # this part of the code handles the permission error if it occurs and prints error message rather than the process not executing.
                except PermissionError as e:
                    permission_error = str(e)
                    print("permission_error")

    # Return the result and file metadata to the template
    return render(request, 'solution.html', {
        'file_path': file_path,
        'mod_time': mod_time,
        'creat_time': creat_time,
        'access_time': access_time,
        'file_size': file_size,
        'file_size1': file_size1,
        'ransomware_alert': ransomware_alert,
        'file_deleted': file_deleted,
        'permission_error': permission_error,
        'name' : name
    })

# this function is used to render the 'Home.html' template    
def home(request):
    return render(request, 'Home.html')

# this function is used to render the 'About.html' template
def about(request):
    return render(request, 'About.html')

# this function is used to render the 'Program.html' template
def programs(request):
    return render(request, 'Program.html')


