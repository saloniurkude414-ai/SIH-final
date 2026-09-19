import os
import hashlib
from datetime import datetime


class ForensicScanner:
    """
    Digital Forensic File Scanner

    Scans a directory without modifying any files and collects
    forensic metadata including SHA-256 hashes.
    """

    def __init__(self):
        self.scanned_files = []
        self.total_files = 0
        self.total_size = 0

    def calculate_hash(self, file_path):
        """Calculate SHA-256 hash of a file."""

        sha256 = hashlib.sha256()

        try:
            with open(file_path, "rb") as file:
                while True:
                    data = file.read(1024 * 1024)

                    if not data:
                        break

                    sha256.update(data)

            return sha256.hexdigest()

        except (PermissionError, OSError):
            return "ACCESS_ERROR"

    def scan_directory(self, directory):
        """
        Recursively scan a directory and collect forensic metadata.
        """

        self.scanned_files = []
        self.total_files = 0
        self.total_size = 0

        if not os.path.isdir(directory):
            raise ValueError("Invalid directory selected.")

        for root, directories, files in os.walk(directory):

            for filename in files:

                file_path = os.path.join(root, filename)

                try:
                    stat = os.stat(file_path)

                    file_size = stat.st_size

                    created_time = datetime.fromtimestamp(
                        stat.st_ctime
                    ).strftime("%Y-%m-%d %H:%M:%S")

                    modified_time = datetime.fromtimestamp(
                        stat.st_mtime
                    ).strftime("%Y-%m-%d %H:%M:%S")

                    accessed_time = datetime.fromtimestamp(
                        stat.st_atime
                    ).strftime("%Y-%m-%d %H:%M:%S")

                    file_extension = os.path.splitext(
                        filename
                    )[1].lower()

                    file_hash = self.calculate_hash(file_path)

                    file_info = {
                        "name": filename,
                        "path": file_path,
                        "extension": file_extension,
                        "size": file_size,
                        "created": created_time,
                        "modified": modified_time,
                        "accessed": accessed_time,
                        "sha256": file_hash
                    }

                    self.scanned_files.append(file_info)

                    self.total_files += 1
                    self.total_size += file_size

                except (PermissionError, OSError):
                    continue

        return self.scanned_files

    def get_summary(self):
        """Return summary information about the scan."""

        return {
            "total_files": self.total_files,
            "total_size": self.total_size
        }