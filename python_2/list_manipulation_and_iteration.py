"""
Rubric criterion: List Manipulation and Iteration
Access and manipulate individual elements in a list and use loops to perform
operations on each element.

Adapted from: logic_1/apply_conditional_logic.py (list + for loop)
"""


def main():
    tasks = ["scan hosts", "review alerts", "write report"]

    # Access individual elements by index.
    print("First task:", tasks[0])
    print("Last task:", tasks[-1])

    # Manipulate an individual element.
    tasks[1] = "triage alerts"
    print("After updating index 1:", tasks)

    # Add and remove elements.
    tasks.append("close ticket")
    tasks.remove("scan hosts")
    print("After append/remove:", tasks)

    # Iterate over each element and perform an operation on it.
    print("\nNumbered task list:")
    for index, task in enumerate(tasks, start=1):
        print(f"  {index}. {task.upper()}")

    # Iterate again and build a new list from each element.
    completed = [task for task in tasks]
    print("\nCompleted list:", completed)


if __name__ == "__main__":
    main()
