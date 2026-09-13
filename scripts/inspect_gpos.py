import json
from pathlib import Path

for path in [Path("data/raw/NORTH"), Path("data/raw/NORTH_CE_PYTHON")]:
    f = list(path.glob("*gpos*.json"))[0]
    with open(f) as fp:
        gpos = json.load(fp)["data"]
    print(f"\n--- GPOs in {path.name} ---")
    for g in gpos:
        name = g.get("Properties", {}).get("name")
        guid = g.get("ObjectIdentifier")
        print(f"GPO: {name} (GUID: {guid})")
        
    f_ous = list(path.glob("*ous*.json"))[0]
    with open(f_ous) as fp:
        ous = json.load(fp)["data"]
    print(f"--- OUs in {path.name} ---")
    for ou in ous:
        print(f"OU: {ou.get('Properties', {}).get('name')} (Links: {ou.get('Links')})")
        
    f_doms = list(path.glob("*domains*.json"))[0]
    with open(f_doms) as fp:
        doms = json.load(fp)["data"]
    print(f"--- Domains in {path.name} ---")
    for d in doms:
        print(f"Domain: {d.get('Properties', {}).get('name')} (Links: {d.get('Links')})")
