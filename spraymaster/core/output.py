import csv
import json
import threading


class OutputManager:
    _FIELDS = ["status", "host", "port", "user", "pass", "protocol"]

    def __init__(self, path: str, fmt: str = "text"):
        self.fmt = fmt
        self._lock = threading.Lock()
        self._file = open(
            path, "w", newline="" if fmt == "csv" else None, encoding="utf-8"
        )
        if fmt == "csv":
            self._writer = csv.DictWriter(
                self._file, fieldnames=self._FIELDS, extrasaction="ignore"
            )
            self._writer.writeheader()

    def write(self, result: dict):
        with self._lock:
            if self.fmt == "text":
                self._file.write(
                    f"[{result['status'].upper()}] "
                    f"{result['host']}:{result['port']} "
                    f"| {result['user']}:{result['pass']}\n"
                )
            elif self.fmt == "json":
                self._file.write(json.dumps(result) + "\n")
            elif self.fmt == "csv":
                self._writer.writerow({k: result.get(k, "") for k in self._FIELDS})
            self._file.flush()

    def close(self):
        self._file.close()
