"""Initialise the SQLite database (run on container start or manually)."""

from .database import DB_PATH, init_db


def main() -> None:
    init_db()
    print(f"database initialised at {DB_PATH}")


if __name__ == "__main__":
    main()
