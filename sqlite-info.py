#!/usr/bin/env python3

import argparse
import logging
import sqlite3
import sqlite3.dbapi2 as dapi

logging.basicConfig(force=True, encoding='utf-8', level=logging.INFO,
                    format='[%(asctime)s] %(message)s', datefmt='%Y-%m-%d %H:%M:%S')

tdbconn = type[dapi.Connection]

def open_db() -> tdbconn:
    # Open db
    conn = sqlite3.connect("users.sqlite")
    return conn

def dump_info(conn: tdbconn) -> None:
    # Format query 
    query = "SELECT * FROM users;"

    # Run query
    res = conn.execute(query)
    logging.info("query: %s\n", query)

    # Print content
    print(res.fetchall())

def finish(conn: tdbconn):
    conn.commit()
    conn.close()

def main():
    # Command line interface
    parser = argparse.ArgumentParser(
        description="""A server-side interface show the content of the database.""",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.parse_args()

    # Read and process input
    logging.info("Running sqlite-info")
    conn = open_db()
    dump_info(conn)
    finish(conn)

if __name__ == "__main__":
    main()
    
