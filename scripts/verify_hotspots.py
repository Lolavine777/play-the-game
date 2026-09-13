import json
from pathlib import Path

DATA_DIR = Path("data/raw/NORTH")

def load_json(name):
    matches = list(DATA_DIR.glob(f"*{name}*.json"))
    if not matches:
        raise FileNotFoundError(f"No file matching {name}")
    with open(matches[0], "r", encoding="utf-8") as f:
        return json.load(f)["data"]

def check_hotspot_1():
    print("\n==========================================")
    print("HOTSPOT 1: Lỗ hổng GPO (STARKWALLPAPER & SAMWELL.TARLY)")
    print("==========================================")
    gpos = load_json("gpos")
    users = load_json("users")
    
    stark_gpo = None
    for g in gpos:
        name = g.get("Properties", {}).get("name", "")
        if "STARKWALLPAPER" in name.upper():
            stark_gpo = g
            print(f"Found GPO: {name} (ID: {g.get('ObjectIdentifier')})")
            print("GPO Properties:", json.dumps(g.get("Properties"), indent=2))
            print(f"GPO Aces count: {len(g.get('Aces', []))}")
            
    samwell = None
    for u in users:
        name = u.get("Properties", {}).get("name", "")
        if "SAMWELL" in name.upper():
            samwell = u
            print(f"\nFound User: {name} (ID: {u.get('ObjectIdentifier')})")
            print("User Properties:", json.dumps(u.get("Properties"), indent=2))
            print(f"User Aces count: {len(u.get('Aces', []))}")

    # Check Aces on GPO targeting Samwell or vice versa
    if stark_gpo and samwell:
        sam_id = samwell.get("ObjectIdentifier")
        print("\nChecking Aces on STARKWALLPAPER targeting SAMWELL.TARLY:")
        for ace in stark_gpo.get("Aces", []):
            if ace.get("PrincipalSID") == sam_id or ace.get("PrincipalSID", "").endswith(sam_id.split("-")[-1]):
                print(f"  -> Match in GPO Aces: {json.dumps(ace)}")
        
        gpo_id = stark_gpo.get("ObjectIdentifier")
        print("\nChecking Aces on SAMWELL targeting STARKWALLPAPER:")
        for ace in samwell.get("Aces", []):
            if ace.get("PrincipalSID") == gpo_id:
                print(f"  -> Match in User Aces: {json.dumps(ace)}")
                
        # Also check all Aces on STARKWALLPAPER
        print("\nAll ACEs on STARKWALLPAPER:")
        for ace in stark_gpo.get("Aces", []):
            print(f"  - Principal: {ace.get('PrincipalSID')} ({ace.get('PrincipalType')}), Right: {ace.get('RightName')}, IsInherited: {ace.get('IsInherited')}")

def check_hotspot_2():
    print("\n==========================================")
    print("HOTSPOT 2: Ủy thác Kerberos (CASTELBLACK -> WINTERFELL)")
    print("==========================================")
    computers = load_json("computers")
    for c in computers:
        name = c.get("Properties", {}).get("name", "")
        print(f"\nComputer: {name} (ID: {c.get('ObjectIdentifier')})")
        props = c.get("Properties", {})
        print(f"  PrimaryGroupSID: {c.get('PrimaryGroupSID')}")
        print(f"  AllowedToDelegate: {c.get('AllowedToDelegate')}")
        print(f"  AllowedToAct: {c.get('AllowedToAct')}")
        print(f"  UnconstrainedDelegation: {props.get('unconstraineddelegation')}")
        print(f"  Enabled: {props.get('enabled')}")
        print(f"  OperatingSystem: {props.get('operatingsystem')}")

def check_hotspot_3():
    print("\n==========================================")
    print("HOTSPOT 3: Lồng nhóm gián tiếp (STARK & REMOTE DESKTOP USERS)")
    print("==========================================")
    groups = load_json("groups")
    stark_groups = []
    rdp_groups = []
    for g in groups:
        name = g.get("Properties", {}).get("name", "")
        if "STARK" in name.upper():
            stark_groups.append(g)
        if "REMOTE DESKTOP" in name.upper() or "RDP" in name.upper():
            rdp_groups.append(g)
            
    print("Found STARK groups:")
    for g in stark_groups:
        print(f"- {g.get('Properties', {}).get('name')} (SID: {g.get('ObjectIdentifier')})")
        print(f"  Members ({len(g.get('Members', []))}): {json.dumps(g.get('Members'), indent=2)}")
        
    print("\nFound RDP groups:")
    for g in rdp_groups:
        print(f"- {g.get('Properties', {}).get('name')} (SID: {g.get('ObjectIdentifier')})")
        print(f"  Members ({len(g.get('Members', []))}): {json.dumps(g.get('Members'), indent=2)}")

if __name__ == "__main__":
    check_hotspot_1()
    check_hotspot_2()
    check_hotspot_3()
