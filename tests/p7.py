import subprocess

def get_uptime():
    # Take an IP address or domain from the user
    server = input("Enter the server address to check uptime: ")

    # Vulnerable: using check_output with shell=True
    command = f"ping -c 1 {server}"
    
    output = subprocess.check_output(command, shell=True)
    print(output.decode())

if __name__ == "__main__":
    get_uptime()
