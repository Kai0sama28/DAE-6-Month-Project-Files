"""
Rubric criterion: Exception Handling
Utilize a try clause to attempt code execution, manage exceptions with an except
clause, use an else clause for code that runs if no exceptions occur, and include
a finally clause to execute code regardless of the previous clauses' results.

Adapted from: ai-agentic-soc/services/triage_api/jobs.py (try / except / else / finally)
and python_1/tracker keeper 2.5.py (try / except around date parsing)
"""


def divide(numerator, denominator):
    """Demonstrate all four clauses of Python's exception-handling structure."""
    try:
        result = numerator / denominator
    except ZeroDivisionError as error:
        print("except: cannot divide by zero ->", error)
        return None
    else:
        print(f"else: no exception; result = {result}")
        return result
    finally:
        print("finally: this always runs, success or failure.")


def main():
    print("Successful division:")
    value = divide(10, 2)
    print("Returned:", value)

    print("\nDivision by zero:")
    value = divide(10, 0)
    print("Returned:", value)


if __name__ == "__main__":
    main()
