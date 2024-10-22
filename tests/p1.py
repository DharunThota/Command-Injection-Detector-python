import subprocess

def delete_file_safe():
    filename = input("Enter the filename to delete: ")

    # Safe usage: pass filename as an argument, avoiding shell injection
    try:
        subprocess.run(["rm", filename], check=True)
    except subprocess.CalledProcessError as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    delete_file_safe()
