import base64
import os
import re
from pathlib import Path

from gvm.connections import UnixSocketConnection
from gvm.protocols.gmp import Gmp
from gvm.transforms import EtreeCheckCommandTransform
from lxml import etree

try:
    from dotenv import load_dotenv
except ImportError:
    pass
else:
    load_dotenv(Path(__file__).with_name(".env"))


SOCKET = os.environ.get("GVM_SOCKET", "/run/gvmd/gvmd.sock")
REPO_DIR = Path(__file__).resolve().parent.parent
OUTPUT_DIR = Path(
    os.environ.get("OUTPUT_DIR", REPO_DIR / "scans" / "vuln-scan")
)


def safe_name(value: str) -> str:
    value = re.sub(r"[^A-Za-z0-9._-]+", "_", value.strip())
    return value.strip("._") or "report"


def report_field(report, path: str) -> str:
    return (report.findtext(f"report/{path}") or report.findtext(path) or "").strip()


def is_completed(report) -> bool:
    status = report_field(report, "scan_run_status")
    return status == "Done" if status else bool(report_field(report, "scan_end"))


def find_csv_format_id(gmp) -> str:
    response = gmp.get_report_formats(filter_string="rows=-1", details=True)
    candidates = []
    for report_format in response.findall("report_format"):
        name = (report_format.findtext("name") or "").strip()
        extension = (report_format.findtext("extension") or "").strip().lower()
        content_type = (report_format.findtext("content_type") or "").strip().lower()
        if extension == "csv" or "csv" in name.lower() or "csv" in content_type:
            candidates.append((report_format.get("id"), name))

    if not candidates:
        raise RuntimeError("No CSV report format is available in gvmd")

    for format_id, name in candidates:
        if name.lower() in {"csv results", "csv"}:
            return format_id
    return candidates[0][0]


def decode_report(response) -> bytes:
    report = response.find("report")
    if report is None:
        raise RuntimeError("The GMP response does not contain a report")

    # Export responses can contain either the base64 payload directly in the
    # report node or in a nested report node, depending on the gvmd version.
    payload = (report.text or "").strip()
    if not payload:
        nested = report.find("report")
        payload = (nested.text or "").strip() if nested is not None else ""
    if not payload:
        report_format = report.find("report_format")
        payload = (report_format.tail or "").strip() if report_format is not None else ""
    if not payload:
        raise RuntimeError("The exported report has no payload")
    return base64.b64decode(payload)


def main() -> None:
    user = os.environ["GVM_USER"]
    password = os.environ["GVM_PASS"]
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    connection = UnixSocketConnection(path=SOCKET)
    with Gmp(connection, transform=EtreeCheckCommandTransform()) as gmp:
        gmp.authenticate(user, password)
        csv_format_id = None
        response = gmp.get_reports(filter_string="rows=-1", details=False)
        all_reports = response.findall("report")
        reports = sorted(
            (report for report in all_reports if is_completed(report)),
            key=lambda report: report_field(report, "scan_end") or report_field(report, "creation_time"),
            reverse=True,
        )

        print(f"Found {len(all_reports)} report(s); {len(reports)} completed")
        seen_directories = set()
        for report in reports:
            report_id = report.get("id")
            task_name = report_field(report, "task/name") or "report"
            report_dir = OUTPUT_DIR / safe_name(task_name.replace("/", "-"))
            if report_dir in seen_directories:
                continue
            seen_directories.add(report_dir)
            report_dir.mkdir(parents=True, exist_ok=True)

            csv_destination = report_dir / "vuln-scan.csv"
            xml_destination = report_dir / "vuln-scan.xml"
            for destination in (csv_destination, xml_destination):
                if destination.exists():
                    print(f"[skip] {destination}")
                    continue
                if destination.suffix == ".csv":
                    if csv_format_id is None:
                        csv_format_id = find_csv_format_id(gmp)
                    csv_response = gmp.get_report(
                        report_id,
                        report_format_id=csv_format_id,
                        ignore_pagination=True,
                        details=True,
                    )
                    data = decode_report(csv_response)
                else:
                    xml_response = gmp.get_report(
                        report_id,
                        ignore_pagination=True,
                        details=True,
                    )
                    data = etree.tostring(
                        xml_response,
                        encoding="UTF-8",
                        xml_declaration=True,
                        pretty_print=False,
                    )
                with destination.open("xb") as output:
                    output.write(data)
                print(f"[saved] {destination} ({len(data)} bytes)")


if __name__ == "__main__":
    main()
