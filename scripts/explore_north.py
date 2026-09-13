import json
from pathlib import Path
from collections import defaultdict

DATA_DIR = Path("data/raw/NORTH")

def main():
    print("=== Exploring NORTH dataset ===")
    json_files = list(DATA_DIR.glob("*.json"))
    for f in sorted(json_files):
        try:
            with open(f, "r", encoding="utf-8") as fp:
                data = json.load(fp)
                meta = data.get("meta", {})
                data_list = data.get("data", [])
                print(f"- {f.name}: count={len(data_list)}, type={meta.get('type')}, version={meta.get('version')}")
        except Exception as e:
            print(f"- Error reading {f.name}: {e}")

if __name__ == "__main__":
    main()
