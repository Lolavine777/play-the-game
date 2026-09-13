import json
from pathlib import Path

for name in ["computers", "users"]:
    f = list(Path("data/raw/NORTH_CE_PYTHON").glob(f"*{name}*.json"))[0]
    with open(f) as fp:
        data = json.load(fp)
    for item in data["data"]:
        atd = item.get("AllowedToDelegate", [])
        if atd:
            print(f"Object: {item.get('Properties', {}).get('name')}")
            print(f"AllowedToDelegate: {json.dumps(atd, indent=2)}")
