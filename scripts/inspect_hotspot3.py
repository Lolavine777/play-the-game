import json
from pathlib import Path

def inspect_group_nesting(dir_path):
    print(f"\n--- Checking Group Nesting in {dir_path.name} ---")
    f_groups = list(dir_path.glob("*groups*.json"))[0]
    with open(f_groups) as fp:
        groups = json.load(fp)["data"]
        
    id_to_group = {g["ObjectIdentifier"]: g for g in groups}
    
    for g in groups:
        name = g.get("Properties", {}).get("name", "")
        if "REMOTE DESKTOP" in name.upper():
            print(f"Group: {name} ({g['ObjectIdentifier']})")
            for m in g.get("Members", []):
                mid = m["ObjectIdentifier"]
                m_obj = id_to_group.get(mid)
                m_name = m_obj.get("Properties", {}).get("name") if m_obj else mid
                print(f"  -> Member: {m_name} ({m['ObjectType']})")
                if m_obj:
                    for sub_m in m_obj.get("Members", []):
                        sub_id = sub_m["ObjectIdentifier"]
                        print(f"     -> Sub-member: {sub_id} ({sub_m['ObjectType']})")

    # Also check which computers have RemoteDesktopUsers
    f_comps = list(dir_path.glob("*computers*.json"))[0]
    with open(f_comps) as fp:
        comps = json.load(fp)["data"]
    for c in comps:
        print(f"Computer: {c.get('Properties', {}).get('name')}")
        print(f"  RemoteDesktopUsers: {c.get('RemoteDesktopUsers')}")
        print(f"  LocalAdmins: {c.get('LocalAdmins')}")
        print(f"  CanRDP (from aces or props):")
        for ace in c.get("Aces", []):
            if "RDP" in ace.get("RightName", ""):
                print(f"    ACE RDP: {ace}")

inspect_group_nesting(Path("data/raw/NORTH"))
inspect_group_nesting(Path("data/raw/NORTH_CE_PYTHON"))
