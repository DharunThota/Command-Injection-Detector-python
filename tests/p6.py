import os

def search_files():
    # Take a filename as input from the user
    filename = input("Enter the filename to search for: ")

    # Vulnerable: using os.popen() with user input
    command = f"find / -name {filename}"
    
    stream = os.popen(command)
    output = stream.read()
    print(output)

if __name__ == "__main__":
    search_files()
