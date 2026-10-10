#!/usr/bin/env python3

import argparse
import json
import subprocess
from pathlib import Path


DOMAIN = "media.cdn.viber.com"


def build_jsonl_output_file_path(input_file):
    output_file = input_file.with_suffix(".jsonl")
    if not output_file.exists():
        return output_file

    for counter in range(1, 1000):
        candidate = input_file.with_name(
            f"{input_file.stem}-{counter}.jsonl"
        )
        if not candidate.exists():
            return candidate

    raise RuntimeError("Could not find an unused output file name")


def load_airport_metadata():
    try:
        import airportsdata
    except ImportError:
        raise RuntimeError(
            "Missing dependency 'airportsdata'. Install it with: "
            "pip install airportsdata"
        )

    airports = airportsdata.load("IATA")
    load_iata_macs = getattr(airportsdata, "load_iata_macs", None)
    multi_airport_cities = load_iata_macs() if load_iata_macs else {}

    return airports, multi_airport_cities


def read_unique_ips(input_file):
    return [
        line.strip()
        for line in input_file.read_text().splitlines()
        if line.strip()
    ]


def reverse_lookup_ip(ip):
    result = subprocess.run(
        ["dig", "-x", ip, "+short"],
        text=True,
        capture_output=True,
        timeout=10,
    )

    return [
        line.strip()
        for line in result.stdout.splitlines()
        if line.strip() and not line.startswith(";;")
    ]


def extract_airport_code(reverse_lookup_names):
    for name in reverse_lookup_names:
        labels = name.strip(".").split(".")
        if len(labels) < 5:
            continue
        if labels[-3:] != ["r", "cloudfront", "net"]:
            continue

        location_label = labels[-4]
        airport_code = "".join(
            character
            for character in location_label
            if character.isalpha()
        )

        if len(airport_code) == 3:
            return airport_code.upper()

    return None


def build_metadata_from_multi_airport_city(airport_code, multi_airport_city):
    airports = multi_airport_city.get("airports", {}).values()
    subdivisions = {
        airport.get("subd")
        for airport in airports
        if airport.get("subd")
    }

    return {
        "airport_code": airport_code,
        "airport_name": f"{multi_airport_city.get('name')} Multi Airport City",
        "city": multi_airport_city.get("name"),
        "country": multi_airport_city.get("country"),
        "domain": DOMAIN,
        "subdivision": subdivisions.pop() if len(subdivisions) == 1 else None,
    }


def build_enriched_ip_record(
    ip,
    airport_code,
    airports,
    multi_airport_cities,
):
    airport = airports.get(airport_code) if airport_code else None

    if airport:
        metadata = {
            "airport_code": airport_code,
            "airport_name": airport.get("name"),
            "city": airport.get("city"),
            "country": airport.get("country"),
            "domain": DOMAIN,
            "subdivision": airport.get("subd"),
        }
    elif airport_code in multi_airport_cities:
        metadata = build_metadata_from_multi_airport_city(
            airport_code,
            multi_airport_cities[airport_code],
        )
    else:
        metadata = {
            "airport_code": airport_code,
            "airport_name": None,
            "city": None,
            "country": None,
            "domain": DOMAIN,
            "subdivision": None,
        }

    metadata["ip"] = ip
    return metadata


def enrich_unique_ips(input_file):
    airports, multi_airport_cities = load_airport_metadata()

    for ip in read_unique_ips(input_file):
        reverse_lookup_names = reverse_lookup_ip(ip)
        airport_code = extract_airport_code(reverse_lookup_names)
        yield build_enriched_ip_record(
            ip,
            airport_code,
            airports,
            multi_airport_cities,
        )


def parse_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "input_file",
        type=Path,
        help="unique-ips.txt file to enrich",
    )
    return parser.parse_args()


def main():
    args = parse_arguments()

    if not args.input_file.exists():
        raise FileNotFoundError(args.input_file)

    output_file = build_jsonl_output_file_path(args.input_file)
    with output_file.open("w") as file:
        for record in enrich_unique_ips(args.input_file):
            file.write(json.dumps(record, sort_keys=True) + "\n")

    print(f"Wrote {output_file}")


if __name__ == "__main__":
    main()
