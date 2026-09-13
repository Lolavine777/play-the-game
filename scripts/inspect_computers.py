import json
from pathlib import Path

f = list(Path("data/raw/NORTH").glob("*computers*.json"))[0]
with open(f, "r") as fp:
    data = json.load(fp)

for comp in data["data"]:
    print("="*50)
    print("Name:", comp.get("Properties", {}).get("name"))
    print("Keys in computer object:", list(comp.keys()))
    for k, v in comp.items():
        if k not in ["Properties", "Aces"]:
            print(f"  {k}: {v}")
    print("Properties:", json.dumps(comp.get("Properties", {}), indent=2))
    print("Aces count:", len(comp.get("Aces", [])))
