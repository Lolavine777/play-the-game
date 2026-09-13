import json
from pathlib import Path
from collections import Counter, defaultdict

def analyze_folder(folder_path):
    print(f"\n==========================================")
    print(f"ANALYZING: {folder_path.name}")
    print(f"==========================================")
    
    edge_counts = Counter()
    objects = {}
    
    for f in folder_path.glob("*.json"):
        with open(f, "r", encoding="utf-8") as fp:
            try:
                content = json.load(fp)
            except Exception as e:
                print(f"Error reading {f.name}: {e}")
                continue
                
            data = content.get("data", [])
            for item in data:
                obj_id = item.get("ObjectIdentifier")
                name = item.get("Properties", {}).get("name") or obj_id
                objects[obj_id] = name
                
                # 1. Aces
                for ace in item.get("Aces", []):
                    right = ace.get("RightName")
                    edge_counts[right] += 1
                    
                # 2. Members
                for m in item.get("Members", []):
                    edge_counts["MemberOf"] += 1
                    
                # 3. AllowedToDelegate
                for atd in item.get("AllowedToDelegate", []):
                    edge_counts["AllowedToDelegate"] += 1
                    
                # 4. AllowedToAct
                for ata in item.get("AllowedToAct", []):
                    edge_counts["AllowedToAct"] += 1
                    
                # 5. HasSIDHistory
                for sid in item.get("HasSIDHistory", []):
                    edge_counts["HasSIDHistory"] += 1
                    
                # 6. PrimaryGroupSID
                if item.get("PrimaryGroupSID"):
                    edge_counts["PrimaryGroupMemberOf"] += 1
                    
                # 7. LocalAdmins / CanRDP / CanPSRemote / ExecuteDCOM
                for x in item.get("LocalAdmins", []):
                    edge_counts["AdminTo"] += 1
                for x in item.get("RemoteDesktopUsers", []):
                    edge_counts["CanRDP"] += 1
                for x in item.get("PSRemoteUsers", []):
                    edge_counts["CanPSRemote"] += 1
                for x in item.get("DcomUsers", []):
                    edge_counts["ExecuteDCOM"] += 1
                    
                # 8. Sessions
                for x in item.get("Sessions", {}).get("Results", []) if isinstance(item.get("Sessions"), dict) else item.get("Sessions", []):
                    edge_counts["HasSession"] += 1
                for x in item.get("PrivilegedSessions", {}).get("Results", []) if isinstance(item.get("PrivilegedSessions"), dict) else item.get("PrivilegedSessions", []):
                    edge_counts["HasPrivilegedSession"] += 1
                for x in item.get("RegistrySessions", {}).get("Results", []) if isinstance(item.get("RegistrySessions"), dict) else item.get("RegistrySessions", []):
                    edge_counts["HasRegistrySession"] += 1
                    
                # 9. ChildObjects / Links
                for link in item.get("Links", []):
                    edge_counts["GPLink"] += 1
                    
    print(f"Total objects found: {len(objects)}")
    print("Edge type frequencies:")
    for edge, count in edge_counts.most_common():
        print(f"  {edge:28s}: {count:5d}")
    return edge_counts, objects

if __name__ == "__main__":
    analyze_folder(Path("data/raw/NORTH"))
    analyze_folder(Path("data/raw/NORTH_CE_PYTHON"))
