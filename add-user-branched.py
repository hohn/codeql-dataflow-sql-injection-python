#!/usr/bin/env python3

import argparse
import logging
import os
import sqlite3
import re


class EmptyNameError(Exception):
    pass


logging.basicConfig(
    force=True,
    encoding="utf-8",
    level=logging.INFO,
    format="[%(asctime)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)


# A class that implements "execute" via a method called "executescript"
class FakeExecuteScriptExample:
    def __init__(self, conn):
        self.conn = conn

    def executescript(self, query: str) -> None:
        self.conn.execute(query)


def get_user_info():
    print("*** Welcome to sql injection ***")
    print("Please enter name: ", end="", flush=True)
    info = input().strip()
    if info == "":
        raise EmptyNameError("get_user_info: expect non-empty name")
    return info


def get_new_id():
    id = os.getpid()
    return id


def execute_query_unsafe(conn, query: str) -> None:
    # Execute query
    conn.executescript(query)  # Unsafe, used for illustration
    logging.info("query: %s\n", query)


def execute_query_checked(conn, query: str) -> None:
    # Execute query
    conn.execute(query)  # Safe, used for illustration
    logging.info("query: %s\n", query)


def execute_query_misleading_name(conn, query: str) -> None:
    # use FakeExecuteScriptExample
    fake_conn = FakeExecuteScriptExample(conn)
    fake_conn.executescript(query)  # Safe, used for illustration


def sanitize(match: str) -> str:
    # actually does nothing. this is just an example
    return match


def execute_query_regex(conn, query: str) -> None:
    match = re.match(r"(.*?)", query)
    conn.executescript(match)  # unsafe

    match = re.match(r"^[a-zA-Z0-9]$", query)
    conn.executescript(match)  # sanitized, safe

    match = re.match(r"(.*?)", query)
    match = sanitize(match)
    conn.executescript(match)  # unsafe


def write_info(mode: int, id: int, info: str) -> None:
    # Open db
    conn = sqlite3.connect("users.sqlite")

    # Format query
    query = "INSERT INTO users VALUES (%d, '%s')" % (id, info)

    # Write data
    if mode == 1:
        execute_query_unsafe(conn, query)
    elif mode == 2:
        execute_query_checked(conn, query)
    elif mode == 3:
        execute_query_misleading_name(conn, query)
    elif mode == 4:
        execute_query_regex(conn, query)
    else:
        raise ValueError("write_info: invalid mode")

    # Finish up
    conn.commit()
    conn.close()


def add_user():
    # Command line interface
    parser = argparse.ArgumentParser(
        description="""A server-side interface to add users to the database.  
            A single user name is read from stdin, actions are logged to stderr""",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "-m",
        "--mode",
        type=int,
        choices=range(1, 5),
        help="mode of operation (1-4)",
        default=1,
    )
    args = parser.parse_args()
    mode = args.mode
    # Read and process input
    logging.info("Running add-user")
    info = get_user_info()
    id = get_new_id()
    write_info(mode, id, info)


if __name__ == "__main__":
    add_user()
