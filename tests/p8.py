import subprocess
import shlex

def run_ping():
    # Take IP address or domain as input from the user
    address = input("Enter the IP address or domain to ping: ")

    # Safely split the command using shlex.split() to prevent injection
    command = f"ping -c 1 {address}"
    
    # Use shlex.split to tokenize the command and safely pass it to subprocess
    args = shlex.split(command)
    
    try:
        # Run the command without using shell=True, which prevents injection
        subprocess.run(args, check=True)
    except subprocess.CalledProcessError as e:
        print(f"Command failed: {e}")
    except FileNotFoundError:
        print("The ping command is not available on your system.")
    except Exception as e:
        print(f"An error occurred: {e}")

if __name__ == "__main__":
    run_ping()
