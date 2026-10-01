import csv
import hashlib
import json
import shutil
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path

import pyudev


def calculate_sha256(file_path):
    sha256_hash = hashlib.sha256()

    with file_path.open("rb") as file:
        while chunk := file.read(8192):
            sha256_hash.update(chunk)

    return sha256_hash.hexdigest()


def get_mount_point(device_name):
    result = subprocess.run(
        [
            "findmnt",
            "-rn",
            "-S",
            device_name,
            "-o",
            "TARGET"
        ],
        capture_output=True,
        text=True
    )

    mount_point = result.stdout.strip()

    if mount_point:
        return Path(mount_point)

    return None


def collect_evidence(source_folder):
    source_folder = Path(source_folder).resolve()

    if not source_folder.exists():
        print(f"Folder does not exist: {source_folder}")
        return

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_folder = Path("evidence_output") / f"case_{timestamp}"
    collected_folder = output_folder / "collected_files"

    collected_folder.mkdir(parents=True, exist_ok=True)

    evidence_report = []

    for file_path in source_folder.rglob("*"):
        if not file_path.is_file():
            continue

        try:
            relative_path = file_path.relative_to(source_folder)
            file_hash = calculate_sha256(file_path)
            file_size = file_path.stat().st_size
            modified_time = datetime.fromtimestamp(
                file_path.stat().st_mtime
            ).isoformat()

            destination = collected_folder / relative_path
            destination.parent.mkdir(parents=True, exist_ok=True)

            shutil.copy2(file_path, destination)

            evidence_report.append({
                "filename": str(relative_path),
                "size_bytes": file_size,
                "sha256": file_hash,
                "modified_time": modified_time
            })

            print(f"Collected: {relative_path}")

        except PermissionError:
            print(f"Permission denied: {file_path}")

        except OSError as error:
            print(f"Could not process {file_path}: {error}")

    report_data = {
        "source_folder": str(source_folder),
        "collection_time": datetime.now().isoformat(),
        "file_count": len(evidence_report),
        "files": evidence_report
    }

    json_report = output_folder / "evidence_report.json"

    with json_report.open("w", encoding="utf-8") as file:
        json.dump(report_data, file, indent=4)

    csv_report = output_folder / "evidence_report.csv"

    with csv_report.open("w", newline="", encoding="utf-8") as file:
        fieldnames = [
            "filename",
            "size_bytes",
            "sha256",
            "modified_time"
        ]

        writer = csv.DictWriter(file, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(evidence_report)

    print()
    print("Evidence collection complete.")
    print(f"Files collected: {len(evidence_report)}")
    print(f"Output folder: {output_folder}")


def handle_device(device):
    if device.get("ID_BUS") != "usb":
        return

    if device.get("DEVTYPE") != "partition":
        return

    device_name = device.device_node

    if not device_name:
        return

    print(f"\nUSB storage detected: {device_name}")
    print("Waiting for Linux to mount the USB...")

    mount_point = None

    for _ in range(30):
        mount_point = get_mount_point(device_name)

        if mount_point:
            break

        time.sleep(1)

    if mount_point is None:
        print("The USB was not mounted automatically.")
        print("Open it in the file manager, then insert it again.")
        return

    print(f"Mounted at: {mount_point}")

    answer = input("Collect files from this USB? [y/N]: ").strip().lower()

    if answer == "y":
        collect_evidence(mount_point)
    else:
        print("Collection cancelled.")


def main():
    print("USB forensic monitor started.")
    print("Insert a USB storage device.")
    print("Press Ctrl+C to stop.\n")

    context = pyudev.Context()
    monitor = pyudev.Monitor.from_netlink(context)
    monitor.filter_by(subsystem="block", device_type="partition")

    observer = pyudev.MonitorObserver(
        monitor,
        callback=lambda action, device: (
            handle_device(device) if action == "add" else None
        ),
        name="usb-monitor"
    )

    observer.start()

    try:
        while True:
            time.sleep(1)

    except KeyboardInterrupt:
        print("\nUSB monitor stopped.")


if __name__ == "__main__":
    main()
