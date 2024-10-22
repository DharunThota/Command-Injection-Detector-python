import subprocess

def run_ping():
    # Take IP address or domain as input from the user
    address = input("Enter the IP address or domain to ping: ")

    # Vulnerable: using shell=True with user input
    command = f"ping -c 1 {address}"
    
    subprocess.Popen(command, shell=True)

if __name__ == "__main__":
    run_ping()
