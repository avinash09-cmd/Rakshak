"""Download the official MITRE ATT&CK Enterprise STIX 2.1 bundle."""
import sys
import urllib.request
from pathlib import Path

URL = ("https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/"
       "enterprise-attack/enterprise-attack.json")
DEST = Path(sys.argv[1] if len(sys.argv) > 1 else "data/enterprise-attack.json")

DEST.parent.mkdir(parents=True, exist_ok=True)
print(f"Downloading {URL} ...")
urllib.request.urlretrieve(URL, DEST)
print(f"Saved {DEST} ({DEST.stat().st_size / 1e6:.1f} MB)")
