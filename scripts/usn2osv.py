#!/usr/bin/env python3
# Author: Eduardo Barretto <eduardo.barretto@canonical.com>
# Copyright (C) 2023 Canonical, Ltd.
#
# This script is distributed under the terms and conditions of the GNU General
# Public License, Version 3 or later. See http://www.gnu.org/copyleft/gpl.html
# for details.
#

from argparse import ArgumentParser, ArgumentDefaultsHelpFormatter
from datetime import datetime

import glob
import json
import os
import sys

USN_URL = "https://ubuntu.com/security/notices"
CVE_URL = "https://ubuntu.com/security"

supported_releases = {
    "trusty": {
        "name": "Ubuntu 14.04 LTS",
        "stamp": 1556593200,
    },
    "xenial": {
        "name": "Ubuntu 16.04 LTS",
        "stamp": 1618963200,
    },
    "bionic": {
        "name": "Ubuntu 18.04 LTS",
        "stamp": 1685539024,
    },
    "focal": {
        "name": "Ubuntu 20.04 LTS",
        "stamp": 1587567600,
    },
    "jammy": {
        "name": "Ubuntu 22.04 LTS",
        "stamp": 1650693600,
    },
    "mantic": {
        "name": "Ubuntu 23.10",
        "stamp": 1697493600,
    },
}


class Affected:
    """Ubuntu specific info"""

    release: str
    source_package: str
    fixed_version: str
    binaries: list[str]
    availability: str

    def __init__(self, release, source, fixed_version, binaries, num_sources, timestamp):
        self.source_package = source
        self.fixed_version = fixed_version
        self.release = release
        self.ecosystem = release["name"].replace(" ", ":")
        self.binaries = []
        self.availability = "No subscription needed"

        bins = {}
        if num_sources == 1:
            for binary in binaries:
                bins.update({binary: binaries[binary]["version"]})
                self._update_availability(binaries, binary, timestamp)
        else:
            for binary in binaries:
                if "source" in binaries[binary]:
                    if binaries[binary]["source"] == source or self._is_kernel_binary(
                        binaries[binary]["source"], source
                    ):
                        bins.update({binary: binaries[binary]["version"]})
                        self._update_availability(binaries, binary, timestamp)
                else:
                    # old USN, need to check per version
                    if binaries[binary]["version"] == fixed_version:
                        bins.update({binary: binaries[binary]["version"]})
                        self._update_availability(binaries, binary, timestamp)

        self.binaries.append(bins)

    def _is_kernel_binary(self, kernel, source):
        if kernel == "linux-signed" + source[5:]:
            return True
        elif kernel == "linux-meta" + source[5:]:
            return True

        return False

    def _update_availability(self, binaries, binary, timestamp):
        if "pocket" in binaries[binary]:
            if binaries[binary]["pocket"] != "security":
                self.availability = "Available with Ubuntu Pro: https://ubuntu.com/pro"
                if ":Pro:" not in self.ecosystem:
                    self.ecosystem = self.ecosystem.replace(":", ":Pro:", 1)
        elif timestamp >= self.release["stamp"]:
            self.availability = "Available with Ubuntu Pro: https://ubuntu.com/pro"
            if ":Pro:" not in self.ecosystem:
                self.ecosystem = self.ecosystem.replace(":", ":Pro:", 1)
        else:
            self.availability = "No subscription required"

    def to_dict(self):
        """Convert to OSV expected format"""
        result = {
            "package": {
                "ecosystem": self.ecosystem,
                "name": self.source_package,
            },
            "ranges": [
                {
                    "type": "ECOSYSTEM",
                    "events": [{"introduced": "0"}, {"fixed": self.fixed_version}],
                }
            ],
            "ecosystem_specific": {
                "binaries": self.binaries,
                "availability": self.availability,
            },
        }

        return result


class Reference:
    """OSV reference format"""

    type: str
    url: str

    def __init__(self, url_type, url):
        self.type = url_type
        self.url = url

    def to_dict(self):
        return self.__dict__


class OSV:
    """OSV structure"""

    id: str
    summary: str
    details: str
    published: str
    modified: str
    affected: list[Affected]
    aliases: list[str]
    related: list[str]
    references: list[Reference]

    def __init__(self, usn_id, summary, description, published, cves, modified=None):
        self.id = usn_id
        self.summary = summary
        self.details = description
        self.aliases = []
        self.related = []
        self.published = published
        self.modified = self.published
        if modified:
            self.modified = modified
        self.affected = []
        self.references = []

        self.references.append(Reference("ADVISORY", f"{USN_URL}/{usn_id}"))
        for cve in cves:
            if "launchpad.net" in cve:
                self.references.append(Reference("REPORT", cve))
            else:
                self.related.append(cve)
                self.references.append(Reference("REPORT", f"{CVE_URL}/{cve}"))

    def to_dict(self):
        return self.__dict__

    def toJson(self):
        return json.dumps(self, default=lambda o: o.to_dict(), indent=2)


def parse_options():
    parser = ArgumentParser(formatter_class=ArgumentDefaultsHelpFormatter)
    parser.add_argument(
        "-i",
        "--input-dir",
        action="store",
        default=None,
        required=True,
        help="directory containing usn json files",
    )
    parser.add_argument(
        "-o",
        "--output-dir",
        action="store",
        default=None,
        required=True,
        help="Directory to store generated OSV files",
    )
    options = parser.parse_args()
    return options


def abort(message):
    print(message, file=sys.stderr)
    sys.exit(1)


def parse_sources(sources, release, binaries, timestamp):
    affected = []
    for source in sources:
        num_sources = len(sources)
        fixed_version = sources[source]["version"]
        affected.append(Affected(release, source, fixed_version, binaries, num_sources, timestamp))

    return affected


def write_osv(path, osv):
    with open(os.path.join(path, f"{osv.id}.json"), "w") as f:
        f.write(osv.toJson())


def usn2osv(output_path, usn):
    osv = None
    releases = usn["releases"].keys()
    for release in releases:
        if release not in supported_releases.keys():
            # only create osv for supported releases
            continue
        else:
            published = datetime.utcfromtimestamp(usn["timestamp"]).isoformat() + "Z"
            modified = None
            if os.path.isfile(os.path.join(output_path, f"{usn['id']}.json")):
                # if osv file already exists
                with open(os.path.join(output_path, f"{usn['id']}.json"), "r") as f:
                    current_osv = json.load(f)
                    if current_osv["modified"] != published:
                        modified = published
                        published = current_osv["published"]
                    else:
                        # USN is unmodified, then return
                        break

            affected = parse_sources(
                usn["releases"][release]["sources"],
                supported_releases[release],
                usn["releases"][release]["allbinaries"],
                usn["timestamp"]
            )

            if not osv:
                osv = OSV(
                    usn["id"],
                    usn["summary"],
                    usn["description"],
                    published,
                    usn["cves"],
                    modified,
                )
            osv.affected = osv.affected + affected

    if osv:
        write_osv(output_path, osv)


def main():
    options = parse_options()

    if not os.path.exists(options.output_dir):
        os.mkdir(options.output_dir, 0o644)
    elif not os.path.isdir(options.output_dir):
        abort("%s is not a directory, exiting." % options.output_dir)

    for filename in glob.glob(os.path.join(options.input_dir, "*.json")):
        with open(filename, "r") as f:
            usn = json.load(f)
            usn2osv(options.output_dir, usn)

    return 0


if __name__ == "__main__":
    exit(main())
