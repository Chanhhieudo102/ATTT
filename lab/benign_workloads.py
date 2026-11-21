"""Legitimate workloads used as hard negatives (label 0) in the PID lab.

They intentionally resemble the simulations' runtime behaviour (heavy CPU, heavy file I/O,
many loopback connections) so a model cannot learn "busy + freshly started = malicious".
Usage: python lab/benign_workloads.py {backup,compute,webserver} SECONDS
"""
from __future__ import annotations

import hashlib
import http.server
import os
from pathlib import Path
import shutil
import socketserver
import sys
import tempfile
import threading
import time
import urllib.request
import zipfile


def backup(deadline: float) -> None:
    """Back up generated documents into zip archives, like a sync/backup client."""
    root = Path(tempfile.mkdtemp(prefix="processguard_lab_benign_"))
    try:
        source = root / "documents"
        source.mkdir()
        for index in range(80):
            (source / f"report_{index:03d}.txt").write_bytes(os.urandom(48 * 1024))
        round_number = 0
        while time.time() < deadline:
            archive = root / f"backup_{round_number % 3}.zip"
            with zipfile.ZipFile(archive, "w", zipfile.ZIP_DEFLATED) as bundle:
                for file in source.iterdir():
                    bundle.write(file, file.name)
            round_number += 1
            time.sleep(0.2)
    finally:
        shutil.rmtree(root, ignore_errors=True)


def compute(deadline: float) -> None:
    """CPU-bound checksum job, like a build or media encoder."""
    block = b"processguard benign compute"
    while time.time() < deadline:
        for _ in range(20000):
            block = hashlib.sha256(block).digest()


def webserver(deadline: float) -> None:
    """Local development web server with several polling clients (loopback only)."""
    class Quiet(http.server.SimpleHTTPRequestHandler):
        def log_message(self, *args):
            pass

    class Server(socketserver.ThreadingMixIn, http.server.HTTPServer):
        daemon_threads = True

    server = Server(("127.0.0.1", 0), Quiet)
    port = server.server_address[1]
    threading.Thread(target=server.serve_forever, daemon=True).start()

    def client() -> None:
        while time.time() < deadline:
            try:
                urllib.request.urlopen(f"http://127.0.0.1:{port}/", timeout=2).read()
            except OSError:
                pass
            time.sleep(0.3)

    workers = [threading.Thread(target=client, daemon=True) for _ in range(10)]
    for worker in workers:
        worker.start()
    while time.time() < deadline:
        time.sleep(0.5)
    server.shutdown()


if __name__ == "__main__":
    mode, seconds = sys.argv[1], max(10, min(600, int(sys.argv[2])))
    {"backup": backup, "compute": compute, "webserver": webserver}[mode](time.time() + seconds)
