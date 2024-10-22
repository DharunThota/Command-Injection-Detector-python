import os

def list_files():
    # Take directory path as input from the user
    directory = input("Enter the directory to list files: ")

    # Vulnerable: directly using user input in os.system()
    command = f"ls {directory}"
    
    os.system(command)

if __name__ == "__main__":
    list_files()
