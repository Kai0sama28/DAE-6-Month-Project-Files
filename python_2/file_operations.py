"""
Rubric criterion: File Operations
Implement code to efficiently read data from a file and to write data to a file.

Adapted from: python_1/tracker keeper 2.5.py
  (save_due_date() writes with open(..., "w"); load_due_date() reads with open(..., "r"))
"""
import os
import tempfile

DATA_FILE = os.path.join(tempfile.gettempdir(), "python_2_file_operations_demo.txt")


def write_tasks(path, tasks):
    """Write each task to a file, one per line."""
    with open(path, "w", encoding="utf-8") as f:
        for task in tasks:
            f.write(task + "\n")


def read_tasks(path):
    """Read all lines from a file and return them as a list."""
    with open(path, "r", encoding="utf-8") as f:
        return [line.strip() for line in f if line.strip()]


def main():
    tasks = ["Collect evidence", "Analyze alerts", "Write report"]
    write_tasks(DATA_FILE, tasks)
    print("Wrote", len(tasks), "tasks to:", DATA_FILE)

    loaded = read_tasks(DATA_FILE)
    print("Read back from file:")
    for task in loaded:
        print("  -", task)

    os.remove(DATA_FILE)
    print("Temporary demo file removed.")


if __name__ == "__main__":
    main()
