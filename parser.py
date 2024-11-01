import ast
import argparse

class CommandInjectionDetector(ast.NodeVisitor):
    def __init__(self):
        # Initialize vulnerable functions dictionary as an instance variable
        self.vulnerable_functions = {
            'os.system': "Use 'subprocess.run()' with a list of arguments instead of a shell command.",
            'subprocess.run': "Avoid using 'shell=True'. Use a list of arguments instead of a string to run commands.",
            'subprocess.call': "Avoid using 'shell=True'. Use a list of arguments instead of a string to run commands.",
            'subprocess.Popen': "Avoid using 'shell=True'. Use 'subprocess.run()' or 'subprocess.Popen()' with a list of arguments.",
            'os.popen': "Avoid using 'os.popen'. Use 'subprocess.run()' with a list of arguments for safety.",
            'eval': "Avoid using 'eval()' as it can execute arbitrary code. Consider using 'ast.literal_eval()' for parsing literals or ensure input is validated and sanitized.",
            'exec': "Avoid using 'exec()' as it can execute arbitrary code. Consider refactoring your code to eliminate the need for 'exec()'.",
            'subprocess.check_output': "Avoid using 'shell=True'. Use a list of arguments instead of a string to run commands."
        }
        self.vulnerabilities = []
        self.safe_usages = {}  # Track cases where shlex.split() is used and associate it with the variable it assigns to

    def visit_Call(self, node):
        func_name = self.get_full_function_name(node.func)

        # Track calls to shlex.split and store the variable assigned to
        if func_name == 'shlex.split':
            parent = self.get_assignment_target(node)
            if parent:
                self.safe_usages[parent] = node

        # Check if the call is a potentially vulnerable function
        if func_name in self.vulnerable_functions:
            is_safe = self.is_safe_usage(node)
            if not is_safe:
                # Check if arguments are dynamic (potentially user input)
                for arg in node.args:
                    if isinstance(arg, ast.Name) or isinstance(arg, ast.BinOp):
                        suggestion = self.vulnerable_functions[func_name]
                        self.vulnerabilities.append((node.lineno, func_name, suggestion))
            else:
                # Safe usage is detected, report it
                print(f"Line {node.lineno}: Safe usage of {func_name} with shlex.split().")

        # Continue walking the AST
        self.generic_visit(node)

    def get_full_function_name(self, func):
        """Safely extract the full function name from AST nodes."""
        if isinstance(func, ast.Attribute):
            if isinstance(func.value, ast.Name):
                return f"{func.value.id}.{func.attr}"
            else:
                return f"<unknown>.{func.attr}"
        elif isinstance(func, ast.Name):
            return func.id
        return "<unknown>"

    def is_safe_usage(self, node):
        """Check if shlex.split() is used before subprocess.Popen() or similar."""
        for arg in node.args:
            if isinstance(arg, ast.Name) and arg.id in self.safe_usages:
                return True  # Safe usage because shlex.split() was used
        return False

    def get_assignment_target(self, node):
        """Get the variable that shlex.split() result is assigned to."""
        parent = getattr(node, 'parent', None)
        if isinstance(parent, ast.Assign):
            for target in parent.targets:
                if isinstance(target, ast.Name):
                    return target.id
        return None

    def report_vulnerabilities(self):
        if not self.vulnerabilities:
            print("No command injection or code execution vulnerabilities detected.")
        else:
            print("Possible Command Injection or Code Execution Vulnerabilities Detected:\n")
            for lineno, func_name, suggestion in self.vulnerabilities:
                print(f"Line {lineno}: Vulnerable call to {func_name}")
                print(f"Suggested fix: {suggestion}\n")


def analyze_code_from_file(filename):
    try:
        with open(filename, 'r') as f:
            source_code = f.read()
    except FileNotFoundError:
        print(f"Error: The file '{filename}' was not found.")
        return

    # Parse the source code into an AST
    try:
        tree = ast.parse(source_code)
    except SyntaxError as e:
        print(f"Syntax error in file '{filename}': {e}")
        return
    
    # Link parent nodes to help with assignment detection
    for node in ast.walk(tree):
        for child in ast.iter_child_nodes(node):
            child.parent = node
    
    # Create a detector instance and visit the nodes
    detector = CommandInjectionDetector()
    detector.visit(tree)

    # Report findings
    detector.report_vulnerabilities()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Static Code Analyzer for Command Injection and Code Execution Detection.')
    parser.add_argument('filename', help='Path to the Python file to be analyzed')

    args = parser.parse_args()
    
    # Analyze the code in the provided file
    analyze_code_from_file(args.filename)
