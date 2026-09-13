import json
from pathlib import Path

f_users = list(Path("data/raw/NORTH").glob("*users*.json"))[0]
with open(f_users) as fp:
    users = json.load(fp)["data"]

for u in users:
    print(f"{u['ObjectIdentifier']}: {u.get('Properties', {}).get('name')} | Desc: {u.get('Properties', {}).get('description')}")
