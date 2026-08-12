import os
import subprocess
import sys
import time

HOST = "127.0.0.1"
PORT = "5432"
USER = "squeeze_test"
DATABASE = "postgres"

ENV = os.environ.copy()
ENV["PGPASSWORD"] = "squeeze123"


def run_psql(sql):
    return subprocess.run(
        [
            "psql",
            "-h", HOST,
            "-p", PORT,
            "-U", USER,
            "-d", DATABASE,
            "-c", sql,
        ],
        env=ENV,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
    )


def run_workload_a():
    print("Starting Workload A: Persistent Connection")
    print("One PostgreSQL connection, multiple queries.")

    sql = """
    SELECT 1;
    SELECT pg_sleep(2);
    SELECT 1;
    SELECT pg_sleep(2);
    SELECT 1;
    SELECT pg_sleep(2);
    SELECT 1;
    SELECT pg_sleep(2);
    SELECT 1;
    """

    run_psql(sql)

    print("Workload A complete.")


def run_workload_b():
    print("Starting Workload B: Connection Churn")
    print("Ten separate PostgreSQL connections.")

    for i in range(10):
        print(f"  Connection {i + 1}/10")
        run_psql("SELECT 1;")
        time.sleep(0.5)

    print("Workload B complete.")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 test_workloads.py [A|B]")
        sys.exit(1)

    choice = sys.argv[1].upper()

    if choice == "A":
        run_workload_a()
    elif choice == "B":
        run_workload_b()
    else:
        print("Invalid choice. Use A or B.")
        sys.exit(1)
