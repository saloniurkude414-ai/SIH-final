import os
import hashlib
from datetime import datetime


class ForensicAnalyzer:

    def __init__(self):
        self.results = []

    # ============================================================
    # SHA-256 CALCULATION
    # ============================================================

    def calculate_sha256(self, file_path):

        sha256 = hashlib.sha256()

        try:

            with open(file_path, "rb") as file:

                while True:

                    data = file.read(1024 * 1024)

                    if not data:
                        break

                    sha256.update(data)

            return sha256.hexdigest()

        except Exception as error:

            return f"ERROR: {error}"

    # ============================================================
    # ANALYZE SINGLE FILE
    # ============================================================

    def analyze_file(self, file_path):

        try:

            file_stat = os.stat(file_path)

            file_name = os.path.basename(file_path)

            file_size = file_stat.st_size

            created_time = datetime.fromtimestamp(
                file_stat.st_ctime
            ).strftime("%Y-%m-%d %H:%M:%S")

            modified_time = datetime.fromtimestamp(
                file_stat.st_mtime
            ).strftime("%Y-%m-%d %H:%M:%S")

            accessed_time = datetime.fromtimestamp(
                file_stat.st_atime
            ).strftime("%Y-%m-%d %H:%M:%S")

            extension = os.path.splitext(
                file_name
            )[1].lower()

            # Calculate the ORIGINAL forensic hash
            original_sha256 = self.calculate_sha256(
                file_path
            )

            result = {

                "file_name": file_name,

                "file_path": file_path,

                "extension": extension,

                "size": file_size,

                "created": created_time,

                "modified": modified_time,

                "accessed": accessed_time,

                # IMPORTANT:
                # This hash is the frozen forensic baseline.
                "original_sha256": original_sha256,

                # Keep sha256 for compatibility.
                "sha256": original_sha256
            }

            self.results.append(result)

            return result

        except Exception as error:

            return {

                "file_name": os.path.basename(
                    file_path
                ),

                "file_path": file_path,

                "error": str(error)
            }

    # ============================================================
    # SCAN DIRECTORY
    # ============================================================

    def scan_directory(self, directory):

        self.results = []

        if not os.path.isdir(directory):

            raise ValueError(
                "Invalid directory selected."
            )

        for root, directories, files in os.walk(
            directory
        ):

            for file_name in files:

                file_path = os.path.join(
                    root,
                    file_name
                )

                self.analyze_file(
                    file_path
                )

        return self.results

    # ============================================================
    # VERIFY FILE INTEGRITY
    # ============================================================

    def verify_integrity(
        self,
        file_path,
        original_hash
    ):

        # --------------------------------------------------------
        # Check whether the evidence still exists
        # --------------------------------------------------------

        if not os.path.exists(file_path):

            return {

                "status": "FILE_NOT_FOUND",

                "original_hash": original_hash,

                "current_hash": None
            }

        # --------------------------------------------------------
        # Calculate CURRENT hash
        # --------------------------------------------------------

        current_hash = self.calculate_sha256(
            file_path
        )

        # --------------------------------------------------------
        # Handle hashing error
        # --------------------------------------------------------

        if current_hash.startswith("ERROR:"):

            return {

                "status": "ERROR",

                "original_hash": original_hash,

                "current_hash": current_hash
            }

        # --------------------------------------------------------
        # Compare ORIGINAL vs CURRENT
        # --------------------------------------------------------

        if current_hash == original_hash:

            return {

                "status": "VERIFIED",

                "original_hash": original_hash,

                "current_hash": current_hash
            }

        else:

            return {

                "status": "MODIFIED",

                "original_hash": original_hash,

                "current_hash": current_hash
            }