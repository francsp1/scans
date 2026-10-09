#!/usr/bin/env python3
"""Merge Nmap and Greenbone XML results into a CSV report."""

from __future__ import annotations

import argparse
import csv
import ipaddress
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

import pandas as pd


NMAP_COLUMNS = [
    "source_network", "hostname", "ip", "port", "transport", "protocol",
    "product", "version", "state", "mac", "vendor",
]
OUTPUT_COLUMNS = [
    "hostname", "ip", "port", "transport", "protocol",
    "product", "version", "state", "mac", "vendor", "nvt_name", "summary",
    "description", "severity", "cvss", "cves", "impact", "solution", "references",
]
JOIN_KEYS = ["source_network", "ip", "port", "transport"]
REPO_DIR = Path(__file__).resolve().parent
DEFAULT_SCANS_DIR = REPO_DIR / "scans"
DEFAULT_EXCLUDE_FILE = REPO_DIR / "networks_excluded.csv"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Join scans/port-scan/<network>/port-scan.xml with "
            "scans/vuln-scan/<network>/vuln-scan.xml."
        )
    )
    parser.add_argument(
        "scans",
        nargs="?",
        default=DEFAULT_SCANS_DIR,
        type=Path,
        help=f"root containing the port-scan and vuln-scan directories (default: {DEFAULT_SCANS_DIR})",
    )
    parser.add_argument(
        "-o", "--output", default="joined-scans-by-ip.csv", type=Path,
        help="CSV sorted by IP, port, transport and NVT name",
    )
    parser.add_argument(
        "--output-cvss", default="joined-scans-by-cvss.csv", type=Path,
        help="CSV sorted by descending CVSS, then NVT name, IP and port",
    )
    parser.add_argument(
        "--exclude-file",
        default=DEFAULT_EXCLUDE_FILE,
        type=Path,
        help="CSV containing network,mask exclusions (default: networks_excluded.csv)",
    )
    parser.add_argument(
        "--exclude",
        action="append",
        default=None,
        metavar="NETWORK",
        help="folder/network to exclude; repeat as needed (none excluded by default)",
    )
    return parser.parse_args()


def network_folder(value: str, mask: str | None = None) -> str:
    value = value.strip()
    if mask is not None or "/" in value:
        cidr = f"{value}/{mask.strip()}" if mask is not None else value
        network = ipaddress.ip_network(cidr, strict=True)
        address = ".".join(f"{part:03d}" for part in network.network_address.packed)
        return f"{address}-{network.prefixlen}"
    return value.rstrip("/").replace("/", "-")


def read_excludes(path: Path) -> set[str]:
    if not path.is_file():
        raise ValueError(f"exclude file does not exist: {path}")
    with path.open(encoding="utf-8-sig", newline="") as source:
        reader = csv.DictReader(
            line for line in source if line.strip() and not line.lstrip().startswith("#")
        )
        if reader.fieldnames != ["network", "mask"]:
            raise ValueError(f"{path}: CSV must have the header: network,mask")
        excludes = set()
        for row in reader:
            try:
                excludes.add(network_folder(row["network"], row["mask"]))
            except (AttributeError, ValueError) as error:
                raise ValueError(f"{path}: invalid network row {row}: {error}") from error
        return excludes


def clean(value: object) -> str:
    return "" if value is None else str(value).strip()


def normalize_port(value: object) -> str:
    value = clean(value)
    if not value:
        return ""
    if value.isdigit():
        return str(int(value))
    if value.endswith(".0") and value[:-2].isdigit():
        return str(int(value[:-2]))
    return value


def first_nonempty(values: pd.Series) -> str:
    for value in values:
        if clean(value):
            return clean(value)
    return ""


def parse_nmap(path: Path, source_network: str) -> pd.DataFrame:
    root = ET.parse(path).getroot()
    rows: list[dict[str, str]] = []

    for host in root.findall("host"):
        ipv4 = host.find("address[@addrtype='ipv4']")
        if ipv4 is None:
            continue
        ip = clean(ipv4.get("addr"))
        hostname_node = host.find("hostnames/hostname")
        hostname = clean(hostname_node.get("name")) if hostname_node is not None else ""
        mac_node = host.find("address[@addrtype='mac']")
        mac = clean(mac_node.get("addr")) if mac_node is not None else ""
        vendor = clean(mac_node.get("vendor")) if mac_node is not None else ""
        ports = host.findall("ports/port")

        if not ports:
            rows.append({
                "source_network": source_network, "hostname": hostname, "ip": ip,
                "port": "", "transport": "", "protocol": "", "product": "",
                "version": "", "state": "", "mac": mac, "vendor": vendor,
            })
            continue

        for port_node in ports:
            service = port_node.find("service")
            state = port_node.find("state")
            rows.append({
                "source_network": source_network,
                "hostname": hostname,
                "ip": ip,
                "port": normalize_port(port_node.get("portid")),
                "transport": clean(port_node.get("protocol")).lower(),
                "protocol": clean(service.get("name")) if service is not None else "",
                "product": clean(service.get("product")) if service is not None else "",
                "version": clean(service.get("version")) if service is not None else "",
                "state": clean(state.get("state")) if state is not None else "",
                "mac": mac,
                "vendor": vendor,
            })

    return pd.DataFrame(rows, columns=NMAP_COLUMNS)


def parse_tags(value: str) -> dict[str, str]:
    tags: dict[str, str] = {}
    for item in value.split("|"):
        key, separator, text = item.partition("=")
        if separator:
            tags[key] = text
    return tags


def read_greenbone(path: Path, source_network: str) -> pd.DataFrame:
    rows: list[dict[str, str]] = []
    # iterparse keeps memory bounded even when Greenbone reports become large.
    for _, result in ET.iterparse(path, events=("end",)):
        if result.tag != "result":
            continue
        nvt = result.find("nvt")
        if nvt is None:
            result.clear()
            continue
        host = result.find("host")
        port_text = clean(result.findtext("port"))
        port_part, separator, transport = port_text.rpartition("/")
        if not separator:
            port_part, transport = port_text, ""
        port = normalize_port(port_part)
        if not port.isdigit():
            port, transport = "", ""
        tags = parse_tags(clean(nvt.findtext("tags")))
        cves = sorted({
            clean(ref.get("id"))
            for ref in nvt.findall("refs/ref")
            if clean(ref.get("type")).lower() == "cve" and clean(ref.get("id"))
        })
        references = sorted({
            (clean(ref.get("type")).lower(), clean(ref.get("id")))
            for ref in nvt.findall("refs/ref")
            if clean(ref.get("type")).lower() != "cve" and clean(ref.get("id"))
        })
        rows.append({
            "source_network": source_network,
            "ip": clean(host.text if host is not None else ""),
            "vuln_hostname": clean(host.findtext("hostname") if host is not None else ""),
            "port": port,
            "transport": clean(transport).lower(),
            "nvt name": clean(result.findtext("name")) or clean(nvt.findtext("name")),
            "summary": tags.get("summary", ""),
            "description": clean(result.findtext("description")),
            "severity": clean(result.findtext("threat")),
            "cvss": clean(result.findtext("severity")) or clean(nvt.findtext("cvss_base")),
            "cves": ", ".join(cves),
            "impact": tags.get("impact", ""),
            "solution": clean(nvt.findtext("solution")) or tags.get("solution", ""),
            "references": "; ".join(
                f"{ref_type}: {ref_id}" if ref_type else ref_id
                for ref_type, ref_id in references
            ),
        })
        result.clear()
    return pd.DataFrame(rows, columns=[
        "source_network", "ip", "vuln_hostname", "port", "transport",
        "nvt name", "summary", "description", "severity", "cvss", "cves", "impact", "solution",
        "references",
    ])


def sortable_ip(value: object) -> tuple[int, int]:
    try:
        parsed = ipaddress.ip_address(clean(value))
        return parsed.version, int(parsed)
    except ValueError:
        return 99, 0


def main() -> int:
    args = parse_args()
    if args.output.resolve() == args.output_cvss.resolve():
        raise ValueError("IP and CVSS output paths must be different")
    if not args.scans.is_dir():
        print(f"ERROR: scan directory does not exist: {args.scans}", file=sys.stderr)
        return 2

    excludes = read_excludes(args.exclude_file)
    try:
        excludes.update(network_folder(item) for item in (args.exclude or []))
    except ValueError as error:
        raise ValueError(f"invalid --exclude network: {error}") from error

    nmap_frames: list[pd.DataFrame] = []
    vuln_frames: list[pd.DataFrame] = []
    processed: list[str] = []
    warnings: list[str] = []

    port_scan_root = args.scans / "port-scan"
    vuln_scan_root = args.scans / "vuln-scan"
    port_networks = {
        path.name for path in port_scan_root.iterdir() if path.is_dir()
    } if port_scan_root.is_dir() else set()
    vuln_networks = {
        path.name for path in vuln_scan_root.iterdir() if path.is_dir()
    } if vuln_scan_root.is_dir() else set()

    if not port_scan_root.is_dir():
        warnings.append(f"scan category directory does not exist: {port_scan_root}")
    if not vuln_scan_root.is_dir():
        warnings.append(f"scan category directory does not exist: {vuln_scan_root}")

    for network in sorted(port_networks | vuln_networks):
        if network in excludes:
            continue
        processed.append(network)
        xml_path = port_scan_root / network / "port-scan.xml"
        vuln_xml_path = vuln_scan_root / network / "vuln-scan.xml"

        if xml_path.exists():
            try:
                nmap_frames.append(parse_nmap(xml_path, network))
            except ET.ParseError as error:
                raise ValueError(f"{xml_path}: invalid Nmap XML: {error}") from error
        else:
            warnings.append(f"{network}: no port-scan.xml")

        if vuln_xml_path.exists():
            try:
                vuln_frames.append(read_greenbone(vuln_xml_path, network))
            except ET.ParseError as error:
                raise ValueError(f"{vuln_xml_path}: invalid Greenbone XML: {error}") from error
        else:
            warnings.append(f"{network}: no vuln-scan.xml")

    ports = pd.concat(nmap_frames, ignore_index=True) if nmap_frames else pd.DataFrame(columns=NMAP_COLUMNS)
    vulns = pd.concat(vuln_frames, ignore_index=True) if vuln_frames else pd.DataFrame()
    if vulns.empty and not len(vulns.columns):
        vulns = pd.DataFrame(columns=["source_network", "ip", "vuln_hostname", "port", "transport"])

    original_nmap_rows = len(ports)
    duplicate_nmap_rows = int(ports.duplicated(JOIN_KEYS).sum())
    ports = ports.drop_duplicates(JOIN_KEYS, keep="first").copy()
    ports["_nmap_id"] = range(len(ports))
    vulns["_vuln_id"] = range(len(vulns))

    metadata = (
        ports.groupby(["source_network", "ip"], as_index=False)
        .agg({"hostname": first_nonempty, "mac": first_nonempty, "vendor": first_nonempty})
    )
    hostname_map = {
        (row.source_network, row.ip): row.hostname
        for row in metadata.itertuples()
        if row.hostname
    }
    for row in vulns.itertuples():
        key = (row.source_network, row.ip)
        if key not in hostname_map and row.vuln_hostname:
            hostname_map[key] = row.vuln_hostname

    is_port_finding = vulns["port"].str.fullmatch(r"\d+").fillna(False)
    port_vulns = vulns[is_port_finding].copy()
    host_vulns = vulns[~is_port_finding].copy()

    merged = ports.merge(port_vulns, on=JOIN_KEYS, how="outer", validate="one_to_many")
    for column in ("hostname", "mac", "vendor"):
        lookup = metadata.set_index(["source_network", "ip"])[column]
        keys = pd.MultiIndex.from_frame(merged[["source_network", "ip"]])
        fallback = pd.Series(lookup.reindex(keys).to_numpy(), index=merged.index)
        merged[column] = merged[column].fillna(fallback)

    host_rows = host_vulns.merge(metadata, on=["source_network", "ip"], how="left", validate="many_to_one")
    for column in ("port", "transport", "protocol", "product", "version", "state"):
        host_rows[column] = ""

    combined = pd.concat([merged, host_rows], ignore_index=True).fillna("")
    combined["hostname"] = [
        hostname or hostname_map.get((network, ip), "")
        for hostname, network, ip in zip(combined["hostname"], combined["source_network"], combined["ip"])
    ]
    combined = combined.rename(columns={"nvt name": "nvt_name"})

    nmap_ids = {int(value) for value in combined["_nmap_id"] if value != ""}
    vuln_ids = {int(value) for value in combined["_vuln_id"] if value != ""}
    if nmap_ids != set(range(len(ports))) or vuln_ids != set(range(len(vulns))):
        raise RuntimeError("internal reconciliation failed: one or more source rows were lost")
    if combined.loc[combined["_vuln_id"] != "", "_vuln_id"].duplicated().any():
        raise RuntimeError("internal reconciliation failed: a Greenbone row was duplicated")

    invalid_ips = sorted({clean(value) for value in combined["ip"] if sortable_ip(value)[0] == 99})
    if invalid_ips:
        warnings.append(f"invalid IP value(s), retained at end of output: {', '.join(invalid_ips)}")
    combined["_ip_sort"] = combined["ip"].map(sortable_ip)
    combined["_port_sort"] = pd.to_numeric(combined["port"], errors="coerce")
    combined["_cvss_sort"] = pd.to_numeric(combined["cvss"], errors="coerce")
    combined = combined.sort_values(
        ["_ip_sort", "_port_sort", "transport", "nvt_name"],
        na_position="last", ignore_index=True,
    )
    result = combined[OUTPUT_COLUMNS]
    args.output.parent.mkdir(parents=True, exist_ok=True)
    result.to_csv(args.output, index=False)
    result_cvss = combined.sort_values(
        ["_cvss_sort", "nvt_name", "_ip_sort", "_port_sort"],
        ascending=[False, True, True, True],
        na_position="last", ignore_index=True,
    )[OUTPUT_COLUMNS]
    args.output_cvss.parent.mkdir(parents=True, exist_ok=True)
    result_cvss.to_csv(args.output_cvss, index=False)

    has_nmap = merged["_nmap_id"].notna()
    has_vuln = merged["_vuln_id"].notna()
    matched_findings = int((has_nmap & has_vuln).sum())
    nmap_only = int((has_nmap & ~has_vuln).sum())
    greenbone_only = int((~has_nmap & has_vuln).sum())
    print(f"Processed networks: {len(processed)}")
    print(f"Excluded networks: {', '.join(sorted(excludes)) or 'none'}")
    print(f"Nmap source rows: {original_nmap_rows} ({duplicate_nmap_rows} duplicate key row(s) removed)")
    print(f"Greenbone source rows: {len(vulns)}")
    print(f"Matched port findings: {matched_findings}")
    print(f"Greenbone-only port findings: {greenbone_only}")
    print(f"Host-level Greenbone findings: {len(host_vulns)}")
    print(f"Nmap ports/hosts without a finding: {nmap_only}")
    print(f"Output rows: {len(result)}")
    print(f"Reconciliation: all {len(ports)} unique Nmap rows and all {len(vulns)} Greenbone rows retained")
    for warning in warnings:
        print(f"WARNING: {warning}", file=sys.stderr)
    print(f"Wrote: {args.output}")
    print(f"Wrote: {args.output_cvss}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, pd.errors.ParserError) as error:
        print(f"ERROR: {error}", file=sys.stderr)
        raise SystemExit(1)
