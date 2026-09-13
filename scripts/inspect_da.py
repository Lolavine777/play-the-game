import json
from pathlib import Path

f_groups = list(Path("data/raw/NORTH").glob("*groups*.json"))[0]
with open(f_groups) as fp:
    groups = json.load(fp)["data"]

for g in groups:
    sid = g["ObjectIdentifier"]
    name = g.get("Properties", {}).get("name", "")
    if sid.endswith("-512") or "DOMAIN ADMINS" in name.upper():
        print(f"Group: {name} ({sid})")
        print(f"Members: {json.dumps(g.get('Members', []), indent=2)}")
        print(f"Aces count: {len(g.get('Aces', []))}")
