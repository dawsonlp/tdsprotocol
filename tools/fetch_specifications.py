"""Download the latest published Microsoft specifications this project is checked against into docs/specification/.

    python3 tools/fetch_specifications.py

Microsoft's specifications belong to Microsoft and are under its Open Specifications terms, so the repository doesn't
hold them (git ignores docs/specification/). The canonical page of each specification lists every revision. The first,
"Published Version", is the latest. Each is saved as <name>_v<publication date>.pdf, the form the code cites
(“MS-TDS v20260617”), so a citation names its file. A file already present is kept. Older revisions are left in place
and listed.

The script uses only the standard library, because it runs before anything else is installed.
"""

import re
import sys
import urllib.request
from pathlib import Path

SPECIFICATIONS = {  # the canonical page of each, on Microsoft Learn
    "MS-TDS": "https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-tds/",
    "MC-SQLR": "https://learn.microsoft.com/en-us/openspecs/windows_protocols/mc-sqlr/",
}
FOLDER = Path(__file__).resolve().parents[1] / "docs" / "specification"


def fetch(url: str) -> bytes:
    request = urllib.request.Request(url, headers={"User-Agent": "tdsprotocol fetch_specifications"})
    with urllib.request.urlopen(request, timeout=60) as response:
        return response.read()


def latest(name: str, page_url: str) -> tuple[str, str, str]:
    """The published version's date (YYYYMMDD), revision and PDF address, from the specification's page."""
    page = fetch(page_url).decode("utf-8", "replace")
    at = page.find("Published Version")
    if at < 0:
        raise SystemExit(f"{name}: {page_url} has no “Published Version” table any more. Microsoft may have changed "
                         "the page; download the PDF by hand and name it as this script would.")
    row = page[at : at + 4000]
    date = re.search(r"(\d{1,2})/(\d{1,2})/(\d{4})", row)
    revision = re.search(r">\s*(\d+\.\d+)\s*<", row)
    pdf = re.search(r'href="([^"]+\.pdf)"', row)
    if not (date and revision and pdf):
        missing = [what for what, found in [("date", date), ("revision", revision), ("PDF link", pdf)] if not found]
        raise SystemExit(f"{name}: the “Published Version” row on {page_url} has no {', '.join(missing)}. Microsoft "
                         "may have changed the page; download the PDF by hand and name it as this script would.")
    month, day, year = (int(x) for x in date.groups())
    return f"{year:04}{month:02}{day:02}", revision.group(1), pdf.group(1)


def main() -> None:
    FOLDER.mkdir(parents=True, exist_ok=True)
    for name, page_url in SPECIFICATIONS.items():
        date, revision, pdf_url = latest(name, page_url)
        target = FOLDER / f"{name.lower()}_v{date}.pdf"
        older = sorted(p.name for p in FOLDER.glob(f"{name.lower()}_*.pdf") if p != target)
        if target.exists():
            print(f"{name} v{date} (revision {revision}): up to date, {target.relative_to(FOLDER.parents[1])}")
        else:
            data = fetch(pdf_url)
            if not data.startswith(b"%PDF"):
                raise SystemExit(f"{name}: {pdf_url} didn't return a PDF (it began {data[:16]!r}); nothing was saved")
            partial = target.with_suffix(".part")
            partial.write_bytes(data)
            partial.replace(target)
            print(f"{name} v{date} (revision {revision}): saved {target.relative_to(FOLDER.parents[1])}, "
                  f"{len(data):,} bytes, from {pdf_url}")
        if older:
            print(f"  older copies, left in place: {', '.join(older)}")
    print(f"Pages: {', '.join(SPECIFICATIONS.values())}")


if __name__ == "__main__":
    sys.exit(main())
