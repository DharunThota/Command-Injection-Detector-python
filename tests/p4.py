def evaluate_expression():
    # Take a mathematical expression from the user
    expr = input("Enter a mathematical expression to evaluate: ")

    # Vulnerable: using eval() on user input
    result = eval(expr)
    print(f"Result: {result}")

if __name__ == "__main__":
    evaluate_expression()
