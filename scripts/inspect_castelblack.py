import json
from pathlib import Path

f = list(Path("data/raw/NORTH").glob("*computers*.json"))[0]
with open(f, "r") as fp:
    data = json.load(fp)

for comp in data["data"]:
    if "CASTELBLACK" in comp.get("Properties", {}).get("name", ""):
        print("="*50)
        print("CASTELBLACK:")
        for k, v in comp.items():
            print(f"Key '{k}': {v}")
