import os
import subprocess
import sys


BASE_DIR = os.path.dirname(os.path.abspath(__file__))
INIT_SCRIPT = os.path.join(BASE_DIR, "init_vuln_lab_db.py")
APP_SCRIPT = os.path.join(BASE_DIR, "vuln_lab_app.py")


def main() -> None:
    python_exe = sys.executable

    # Step 1: Initialize / reset the lab database.
    subprocess.run([python_exe, INIT_SCRIPT], check=True)

    # Step 2: Start the vulnerable lab app (blocking process).
    subprocess.run([python_exe, APP_SCRIPT], check=True)


if __name__ == "__main__":
    main()
