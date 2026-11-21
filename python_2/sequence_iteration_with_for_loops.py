"""
Rubric criterion: Sequence Iteration with for Loops
Code a for loop to systematically iterate over a range or collection.

Adapted from: logic_1/apply_conditional_logic.py (for x in list) and
python_1/tracker keeper 2.5.py (for session in range(...))
"""


def main():
    numbers = [2, 3, 4, 5, 6, 7]

    # Iterate systematically over a range.
    print("Work sessions:")
    for session in range(1, 5):
        print(f"  Session {session}")

    # Iterate over a collection.
    print("\nNumbers and their doubles:")
    for x in numbers:
        print(f"  {x} -> {x * 2}")

    # Same pattern as logic_1/apply_conditional_logic.py:
    # find the first odd number greater than 4.
    print("\nFirst odd number greater than 4:")
    for x in numbers:
        if x % 2 == 1 and x > 4:
            print(f"  {x}")
            break


if __name__ == "__main__":
    main()
