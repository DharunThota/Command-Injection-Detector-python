import subprocess

def run_command():
    # Take a system command from the user
    command = input("Enter the command to run: ")

    # Vulnerable: using subprocess.call() with shell=True
    subprocess.call(command, shell=True)

if __name__ == "__main__":
    run_command()
