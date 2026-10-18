"""Download Dataset 2 from the official Cardiff University Figshare record."""
from __future__ import annotations

from pathlib import Path
from urllib.request import Request, urlopen
from zipfile import ZipFile
import argparse
import io
import sys
import json

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

ARTICLE_API = "https://api.figshare.com/v2/articles/27052333"


def download(output: Path = ROOT / "data/raw/cardiff_data_2.csv") -> Path:
    output.parent.mkdir(parents=True, exist_ok=True)
    metadata_request = Request(ARTICLE_API, headers={"User-Agent": "ProcessGuard student research project"})
    with urlopen(metadata_request, timeout=30) as response:
        metadata = json.loads(response.read().decode("utf-8"))
    archives = [file for file in metadata.get("files", []) if file.get("name", "").lower().endswith(".zip")]
    if len(archives) != 1:
        raise RuntimeError("Could not identify the single ZIP file in the Cardiff Figshare record.")
    request = Request(archives[0]["download_url"], headers={"User-Agent": "ProcessGuard student research project"})
    with urlopen(request, timeout=90) as response:
        archive_bytes = response.read()
        if not archive_bytes.startswith(b"PK"):
            raise RuntimeError(f"Figshare did not return a ZIP archive (HTTP content-type: {response.headers.get('Content-Type')}).")
    with ZipFile(io.BytesIO(archive_bytes)) as archive:
        matches = [entry for entry in archive.infolist() if Path(entry.filename).name.lower() == "data_2.csv"]
        if len(matches) != 1:
            raise RuntimeError("The Cardiff archive did not contain exactly one data_2.csv file.")
        with archive.open(matches[0]) as source, output.open("wb") as target:
            target.write(source.read())
    print(f"Saved official Cardiff Dataset 2 to {output}")
    print("Source: https://doi.org/10.17035/d.2018.0050524986 (CC BY 4.0)")
    return output


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, default=ROOT / "data/raw/cardiff_data_2.csv")
    args = parser.parse_args()
    download(args.output)
