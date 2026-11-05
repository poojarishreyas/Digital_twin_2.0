"""Public files for the spec-only services (Mosquitto, MongoDB, MariaDB).
Same pipeline as collect.py: code search -> raw reads into a scratch directory
outside the repository.  Run: python3 collect_new.py search|fetch"""
import json
import os
import sys
from pathlib import Path

import collect

collect.RAW = Path(os.environ.get("RW_RAW_NEW", "/tmp/fidelity-rw-raw-new"))
collect.RAW.mkdir(parents=True, exist_ok=True)
collect.QUERIES = {
    "mosquitto": ["filename:mosquitto.conf allow_anonymous", "filename:mosquitto.conf listener", "filename:mosquitto.conf password_file"],
    "mongodb": ["filename:mongod.conf bindIp", "filename:mongod.conf authorization", "filename:mongod.conf net"],
    "mariadb": ["filename:my.cnf bind-address", "filename:my.cnf mysqld skip-name-resolve", "filename:my.cnf skip-grant-tables",
                "filename:my.cnf mysqld max_connections"],
}
if __name__ == "__main__":
    {"search": collect.search, "fetch": collect.fetch}[sys.argv[1]]()
