#!/usr/bin/env python3

import ipaddress
import re
import subprocess
from datetime import datetime
from pathlib import Path
import argparse
import time


PREFIX_LENGTH = 24
SAMPLE_EVERY = 256

DOMAIN = "do2gy2kwak9k2.cloudfront.net"
QUERY_RATE = -1#300
ITERATIONS = 20
RETRIES = 1

BASE_DIR = Path(__file__).resolve().parent
ECSPLORER_DIR = BASE_DIR.parent / "ECSplorer"
ECSPLORER_SOURCE_DIR = ECSPLORER_DIR / "src"
ECSPLORER_BINARY = ECSPLORER_SOURCE_DIR / "ecsplorer"


SUBNET_FILE = BASE_DIR / "subnets.txt"
INPUT_FILE = BASE_DIR / "domain.txt"
RESULT_DIR = BASE_DIR / "result"

IP_PATTERN = re.compile(
    r"(?<![0-9.])(?:[0-9]{1,3}[.]){3}[0-9]{1,3}(?![0-9.])"
)


def format_duration(seconds):
    seconds = int(seconds)
    hours, seconds = divmod(seconds, 3600)
    minutes, seconds = divmod(seconds, 60)
    return f"{hours:02d}:{minutes:02d}:{seconds:02d}"


def run_command(arguments, cwd=None, capture_output=False):
    return subprocess.run(
        arguments,
        cwd=cwd,
        text=True,
        check=True,
        capture_output=capture_output,
    )


def command_output(arguments):
    result = run_command(arguments, capture_output=True)
    return result.stdout.strip()


def generate_subnets():
    # subnet_size = 2 ** (32 - PREFIX_LENGTH)
    # step = SAMPLE_EVERY * subnet_size
    # Remove above, if not testing in sampling mode, only the line below is necessary
    step = 2 ** (32 - PREFIX_LENGTH)
    subnets = []

    for value in range(0, 2**32, step):
        network = ipaddress.ip_network(
            f"{ipaddress.IPv4Address(value)}/{PREFIX_LENGTH}"
        )

        if network.network_address.is_global:
            subnets.append(str(network))

    SUBNET_FILE.write_text("\n".join(subnets) + "\n")
    print(f"Generated {len(subnets)} subnets")


def find_authoritative_server():
    name_servers = command_output(
        ["dig", "+short", "NS", DOMAIN]
    ).splitlines()

    if not name_servers:
        raise RuntimeError(f"No authoritative name server found for {DOMAIN}")

    name = name_servers[0].rstrip(".")

    addresses = command_output(
        ["dig", "+short", "A", name]
    ).splitlines()

    if not addresses:
        raise RuntimeError(f"Could not resolve an address for {name}")

    return name, addresses[0]


def find_unique_ips(text, excluded_ips):
    addresses = set()

    for value in IP_PATTERN.findall(text):
        try:
            address = ipaddress.ip_address(value)
        except ValueError:
            continue

        if address not in excluded_ips:
            addresses.add(str(address))

    return sorted(addresses, key=ipaddress.ip_address)

def parse_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--nameserver",
        help="Nameserver IP address or hostname to use",
    )
    return parser.parse_args()

def main():
    arguments = parse_arguments()

    generate_subnets()

    if arguments.nameserver is None:
        name_server, name_server_ip = find_authoritative_server()
    else:
        name_server = "Custom"
        name_server_ip = arguments.nameserver

    print(f"Using name server: {name_server} ({name_server_ip})")

    # TODO Rewrite with -resolver instead of writing the custom resolver in the input file, might be faster, remove find_authoritative_server as ECSplorer does it on it's own when no resolver is given
    
    INPUT_FILE.write_text(f"{DOMAIN},{name_server_ip}\n")

    timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    scan_directory = RESULT_DIR / f"scan-{timestamp}"
    log_file = RESULT_DIR / f"scan-{timestamp}.log"
    unique_ips_file = RESULT_DIR / f"unique-ips-{timestamp}.txt"

    RESULT_DIR.mkdir(exist_ok=True)

    arguments = [
        str(ECSPLORER_BINARY),
        f"-query-list={SUBNET_FILE}",
        f"-if={INPUT_FILE}",
        f"-out={scan_directory}",
        f"-query-rate={QUERY_RATE}",
        f"-ni={ITERATIONS}",
        f"-retries={RETRIES}",
        "-pr",
    ]

    print("Running ECSplorer...")

    result = subprocess.run(
        arguments,
        text=True,
        capture_output=True,
    )

    scan_output = result.stdout + result.stderr
    log_file.write_text(scan_output)

    if result.returncode != 0:
        print(scan_output)
        raise RuntimeError(
            f"ECSplorer exited with status {result.returncode}"
        )

    unique_ips = find_unique_ips(
        scan_output,
        {ipaddress.ip_address(name_server_ip)},
    )

    unique_ips_file.write_text("\n".join(unique_ips) + "\n")

    elapsed = format_duration(time.monotonic() - start_time)

    print(f"Scan results: {scan_directory}")
    print(f"Log file: {log_file}")
    print(f"Unique IPs: {unique_ips_file}")
    print(f"Unique IP count: {len(unique_ips)}")
    print(f"Elapsed time: {elapsed}")


if __name__ == "__main__":
    main()
