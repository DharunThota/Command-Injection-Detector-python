import os
import subprocess
from flask import Flask, request

app = Flask(__name__)

# Vulnerable to command injection via subprocess.Popen with shell=True
@app.route('/run', methods=['POST'])
def run():
    command = request.form['command']
    subprocess.Popen(command, shell=True)  # Vulnerable: shell=True allows arbitrary command execution
    return "Command executed!"

# Vulnerable to command injection via eval() function
@app.route('/calc', methods=['POST'])
def calc():
    expression = request.form['expression']
    result = eval(expression)  # Vulnerable: eval can execute arbitrary code
    return f"Result: {result}"

# Vulnerable to command injection via subprocess.run with shell=True
@app.route('/execute', methods=['POST'])
def execute():
    command = request.form['command']
    subprocess.run(command, shell=True)  # Vulnerable: shell=True allows arbitrary command execution
    return "Command executed!"
  
if __name__ == '__main__':
    app.run(debug=True)
