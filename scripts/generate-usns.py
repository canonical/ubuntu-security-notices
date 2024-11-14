#!/usr/bin/env python3
# Author: Eduardo Barretto <eduardo.barretto@canonical.com>
# Copyright (C) 2023 Canonical, Ltd.
#
# This script is distributed under the terms and conditions of the GNU General
# Public License, Version 3 or later. See http://www.gnu.org/copyleft/gpl.html
# for details.
#

from argparse import ArgumentParser, ArgumentDefaultsHelpFormatter

import glob
import json
import os
import re
import sys

try:
    import cPickle as pickle
except ImportError:
    import pickle

DATABASE_FILENAME = "usn.pickle"


def parse_options():
    parser = ArgumentParser(formatter_class=ArgumentDefaultsHelpFormatter)
    parser.add_argument(
        "--db",
        "--database",
        action="store",
        default=DATABASE_FILENAME,
        required=True,
        help="Use specified database file",
    )
    parser.add_argument(
        "-o",
        "--output-dir",
        action="store",
        default=None,
        required=True,
        help="Directory to store generated USN JSON files",
    )
    options = parser.parse_args()
    return options


def abort(message):
    print(message, file=sys.stderr)
    sys.exit(1)


def load_database(filename):
    filename = os.path.expanduser(filename)
    if not os.path.isfile(filename):
        abort("Database %s does not exist, aborting" % filename)
    with open(filename, "rb") as f:
        if sys.version_info[0] == 2:
            database = pickle.load(f)
        else:
            database = pickle.load(f, encoding="utf-8")

    return database


def list_usn_files(path):
    usn_files = []
    for filename in glob.glob(os.path.join(path, "*.json")):
        usn_files.append(filename)

    return usn_files


def load_usn_file(path, usn_id):
    db = {}
    filename = os.path.join(path, f"{usn_id}.json")
    with open(filename, "r") as f:
        db = json.load(f)

    return db


def prepend_usn_to_id(usn, usn_id):
    if re.search(r"^[0-9]+-[0-9]+$", usn_id):
        usn[usn_id]["id"] = "USN-" + usn_id


def write_json(path, data, usn_id):
    with open(os.path.join(path, f"{usn_id}.json"), "w") as f:
        json.dump(data, f, indent=2)


def main():
    options = parse_options()

    if not os.path.exists(options.output_dir):
        os.mkdir(options.output_dir, 0o775)
    elif not os.path.isdir(options.output_dir):
        abort("%s is not a directory, exiting." % options.output_dir)

    database = load_database(options.db)

    for usn_id in database.keys():
        if os.path.exists(
            os.path.join(options.output_dir, f"{database[usn_id]['id']}.json")
        ):
            usn_file = load_usn_file(options.output_dir, usn_id)
            prepend_usn_to_id(database, usn_id)
            if usn_file != database[usn_id]:
                write_json(options.output_dir, database[usn_id], usn_id)
        else:
            prepend_usn_to_id(database, usn_id)
            write_json(options.output_dir, database[usn_id], usn_id)

    usn_files = list_usn_files(options.output_dir)
    for file in usn_files:
        usn_id = file.split("/")[1].split(".")[0]
        if usn_id not in database.keys():
            print(f"{usn_id} deleted from database")
            os.remove(file)

    return 0


if __name__ == "__main__":
    exit(main())
