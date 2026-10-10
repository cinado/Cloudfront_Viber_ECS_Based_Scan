#!/usr/bin/env python3

import ipaddress
import ast
import csv
import subprocess
from collections import Counter
from datetime import datetime
from pathlib import Path
import argparse
import time


DEFAULT_SUBNET_PREFIX_LENGTH = 24
DEFAULT_SAMPLE_EVERY = 1

DOMAIN = "do2gy2kwak9k2.cloudfront.net"
QUERY_RATE = 300
LOG_LEVEL = 1
IP_GENERATORS = 20
RETRIES = 1

ERROR_NAMES = {
    "0": "NO_ERR",
    "1": "NO_AUTH",
    "2": "NO_ADD",
    "3": "NO_EDNS",
    "4": "NO_ECS",
    "5": "WRONG_FAM",
    "6": "SCOPE_OOB",
    "7": "NO_ANS",
    "8": "NO_REC",
    "9": "INTERNAL_ERR",
    "10": "WRONG_PARAM",
    "11": "TRUNCATED_NO_TCP",
}

BASE_DIR = Path(__file__).resolve().parent
ECSPLORER_DIR = BASE_DIR.parent / "ECSplorer"
ECSPLORER_SOURCE_DIR = ECSPLORER_DIR / "src"
ECSPLORER_BINARY = ECSPLORER_SOURCE_DIR / "ecsplorer"


SUBNET_DIR = BASE_DIR / "subnets"
INPUT_FILE = BASE_DIR / "domain.txt"
RESULT_DIR = BASE_DIR / "result"

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


def dig_records(record_type, name):
    output = command_output(["dig", "+short", record_type, name])
    return [
        line.strip().rstrip(".")
        for line in output.splitlines()
        if line.strip()
    ]


def resolve_authoritative_nameserver_ip(domain):
    nameservers = dig_records("NS", domain)
    if not nameservers:
        raise RuntimeError(f"No authoritative NS records found for {domain}")

    for nameserver in sorted(nameservers):
        addresses = []
        for value in dig_records("A", nameserver):
            try:
                address = ipaddress.ip_address(value)
            except ValueError:
                continue

            if address.version == 4:
                addresses.append(address)

        if addresses:
            return str(sorted(addresses)[0])

    raise RuntimeError(
        f"No IPv4 addresses found for authoritative NS records of {domain}"
    )


def build_subnet_query_list_cache_file_path(prefix_length, sample_every):
    if sample_every == 1:
        filename = f"{prefix_length}_subnet.txt"
    else:
        filename = f"{prefix_length}_subnet_{sample_every}_sampled.txt"

    return SUBNET_DIR / filename


def generate_global_ipv4_subnet_query_list_file(
    output_file,
    prefix_length,
    sample_every,
):
    subnet_size = 2 ** (32 - prefix_length)
    step = sample_every * subnet_size
    subnet_count = 0

    with output_file.open("w") as file:
        for value in range(0, 2**32, step):
            network = ipaddress.ip_network(
                f"{ipaddress.IPv4Address(value)}/{prefix_length}"
            )

            if network.network_address.is_global:
                file.write(f"{network}\n")
                subnet_count += 1

    print(f"Generated {subnet_count} subnets: {output_file}")


def get_or_create_subnet_query_list_file(prefix_length, sample_every):
    SUBNET_DIR.mkdir(exist_ok=True)
    subnet_file = build_subnet_query_list_cache_file_path(
        prefix_length,
        sample_every,
    )

    if subnet_file.exists():
        print(f"Using cached subnets: {subnet_file}")
        return subnet_file

    generate_global_ipv4_subnet_query_list_file(
        subnet_file,
        prefix_length,
        sample_every,
    )
    return subnet_file


def find_unique_ips(results_file):
    addresses = set()

    with results_file.open(newline="") as file:
        reader = csv.DictReader(file)
        for row in reader:
            raw_answers = row.get("answers", "")
            if not raw_answers:
                continue

            try:
                answers = ast.literal_eval(raw_answers)
            except (SyntaxError, ValueError):
                continue

            for value in answers:
                try:
                    address = ipaddress.ip_address(value)
                except ValueError:
                    continue

                addresses.add(str(address))

    return sorted(addresses, key=ipaddress.ip_address)


def count_result_errors(results_file):
    errors = Counter()

    with results_file.open(newline="") as file:
        reader = csv.DictReader(file)
        for row in reader:
            error_code = row.get("error", "")
            if error_code:
                errors[ERROR_NAMES.get(error_code, error_code)] += 1

    return errors


def parse_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--nameserver",
        help="Nameserver IP address to use",
    )
    parser.add_argument(
        "--query-rate",
        type=int,
        default=QUERY_RATE,
        help=f"ECSplorer query rate per second (default: {QUERY_RATE})",
    )
    parser.add_argument(
        "--log-level",
        type=int,
        default=LOG_LEVEL,
        help=f"ECSplorer log level, 0-3 (default: {LOG_LEVEL})",
    )
    parser.add_argument(
        "--subnet-prefix-length",
        type=int,
        default=DEFAULT_SUBNET_PREFIX_LENGTH,
        help=(
            "IPv4 subnet prefix length for ECS queries "
            f"(default: {DEFAULT_SUBNET_PREFIX_LENGTH})"
        ),
    )
    parser.add_argument(
        "--sample-every",
        type=int,
        default=DEFAULT_SAMPLE_EVERY,
        help=(
            "Use every Nth subnet; 1 disables sampling "
            f"(default: {DEFAULT_SAMPLE_EVERY})"
        ),
    )
    args = parser.parse_args()

    if args.subnet_prefix_length < 1 or args.subnet_prefix_length > 32:
        parser.error("--subnet-prefix-length must be between 1 and 32")
    if args.sample_every < 1:
        parser.error("--sample-every must be at least 1")

    return args


def main():
    start_time = time.monotonic()
    args = parse_arguments()

    subnet_query_list_file = get_or_create_subnet_query_list_file(
        args.subnet_prefix_length,
        args.sample_every,
    )

    name_server_ip = args.nameserver
    use_resolver = name_server_ip is not None

    if name_server_ip is None:
        name_server_ip = resolve_authoritative_nameserver_ip(DOMAIN)
        print(f"Using name server: Authoritative NS ({name_server_ip})")
    else:
        print(f"Using name server: Custom ({name_server_ip})")

    INPUT_FILE.write_text(f"{DOMAIN},{name_server_ip}\n")

    timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    scan_directory = RESULT_DIR / f"scan-{timestamp}"
    log_file = RESULT_DIR / f"scan-{timestamp}.log"
    unique_ips_file = RESULT_DIR / f"unique-ips-{timestamp}.txt"

    RESULT_DIR.mkdir(exist_ok=True)

    arguments = [
        str(ECSPLORER_BINARY),
        f"-query-list={subnet_query_list_file}",
        f"-if={INPUT_FILE}",
        f"-out={scan_directory}",
        f"-query-rate={args.query_rate}",
        f"-ni={IP_GENERATORS}",
        f"-ll={args.log_level}",
        f"-retries={RETRIES}",
    ]

    if use_resolver:
        arguments.append(f"-resolver={name_server_ip}")

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

    results_file = scan_directory / "ecsresults.csv"
    if not results_file.exists():
        raise RuntimeError(f"ECSplorer did not create {results_file}")

    unique_ips = find_unique_ips(results_file)
    error_counts = count_result_errors(results_file)

    unique_ips_file.write_text("\n".join(unique_ips) + "\n")

    elapsed = format_duration(time.monotonic() - start_time)

    print(f"Scan results: {scan_directory}")
    print(f"Log file: {log_file}")
    print(f"Unique IPs: {unique_ips_file}")
    print(f"Unique IP count: {len(unique_ips)}")
    print(f"ECSplorer result errors: {dict(sorted(error_counts.items()))}")
    print(f"Elapsed time: {elapsed}")


if __name__ == "__main__":
    main()
