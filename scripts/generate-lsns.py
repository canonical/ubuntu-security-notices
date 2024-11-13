#!/usr/bin/env python3
# Author: Eduardo Barretto <eduardo.barretto@canonical.com>
# Copyright (C) 2024 Canonical, Ltd.
#
# This script is distributed under the terms and conditions of the GNU General
# Public License, Version 3 or later. See http://www.gnu.org/copyleft/gpl.html
# for details.
#
from argparse import ArgumentParser, ArgumentDefaultsHelpFormatter

import datetime
import json
import requests
import os


def parse_options():
    parser = ArgumentParser(formatter_class=ArgumentDefaultsHelpFormatter)
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


def query_data(offset):
    url = "https://ubuntu.com/security/notices.json?order=newest&details=LSN"
    if offset:
        url = url + "&offset=" + str(offset)

    response = {}
    try:
        response = requests.get(url).json()
    except:
        print("ERROR: Failed to establish connection")

    return response


# The LSN JSON available in the website differs from the
# Security Notices schema. Therefore we convert it to this
# schema to make sure both USNs and LSNs here are in the
# same format.
def convert_lsn(notice, lsn_id):
    data = {}
    data["action"] = notice["instructions"]
    data["cves"] = notice["cves_ids"]
    data["description"] = notice["description"]
    data["id"] = notice["id"]
    data["isummary"] = notice["summary"]
    data["releases"] = {}
    for release in notice["release_packages"]:
        data["releases"][release] = {"sources": {}, "binaries": {}, "allbinaries": {}}
        for item in notice["release_packages"][release]:
            # lsn json have two entries for same source
            # one containing the binary as version and
            # another with the livepatch module version
            if not item["is_source"]:
                continue
            data["releases"][release]["sources"][item["name"]] = {
                "version": item["version"],
                "description": item["description"],
            }
            version = item["version"].replace(".", "_")
            module_name = (
                "lkp_Ubuntu_"
                + version.split("-")[0]
                + r"[_|\d]+_"
                + item["name"].split("-")[0]
                + r"_(\d+)"
            )
            data["releases"][release]["allbinaries"][item["name"]] = {
                "pocket": "livepatch",
                "module": module_name,
                "version": lsn_id.split("-")[1].lstrip("0"),
            }
    data["summary"] = notice["title"]
    date = datetime.datetime.strptime(notice["published"], "%Y-%m-%dT%H:%M:%S")
    data["timestamp"] = datetime.datetime.timestamp(date)
    data["title"] = notice["title"]
    return data


def write_json(path, data, lsn_id):
    with open(os.path.join(path, f"{lsn_id}.json"), "w") as f:
        json.dump(data, f, indent=2)


def main():
    options = parse_options()

    if not os.path.exists(options.output_dir):
        os.mkdir(options.output_dir, 0o775)
    elif not os.path.isdir(options.output_dir):
        abort("%s is not a directory, exiting." % options.output_dir)

    total = 20
    offset = 0
    while offset < total:
        data = query_data(offset)
        if not data:
            return 0
        total = data["total_results"]
        for notice in data["notices"]:
            lsn_id = notice["id"]
            if os.path.exists(os.path.join(options.output_dir, f"{lsn_id}.json")):
                break
            else:
                data = convert_lsn(notice, lsn_id)
                write_json(options.output_dir, data, lsn_id)

        offset += 20

    return 0


if __name__ == "__main__":
    main()
