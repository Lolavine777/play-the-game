import json
from pathlib import Path
from collections import defaultdict, Counter

DATA_DIR = Path("data/raw/NORTH")

def inspect_all():
    print("=== DEEP INSPECTION OF NORTH DATASET ===")
    json_files = list(DATA_DIR.glob("*.json"))
    
    # Store all objects by SID/ObjectIdentifier
    objects_by_id = {}
    
    # Check delegation attributes
    delegation_findings = []
    
    # Count edge types
    edge_counts = Counter()
    edge_examples = defaultdict(list)
    
    for f in json_files:
        with open(f, "r", encoding="utf-8") as fp:
            content = json.load(fp)
            items = content.get("data", [])
            for item in items:
                obj_id = item.get("ObjectIdentifier")
                props = item.get("Properties", {})
                obj_type = item.get("Properties", {}).get("type") or content.get("meta", {}).get("type")
                name = props.get("name") or props.get("distinguishedname") or obj_id
                objects_by_id[obj_id] = {"name": name, "type": obj_type, "file": f.name}
                
                # Check delegation in props or top-level
                if item.get("AllowedToDelegate"):
                    delegation_findings.append((name, "AllowedToDelegate", item.get("AllowedToDelegate")))
                if item.get("AllowedToAct"):
                    delegation_findings.append((name, "AllowedToAct", item.get("AllowedToAct")))
                if props.get("unconstraineddelegation"):
                    delegation_findings.append((name, "UnconstrainedDelegation", True))
                if props.get("trustedtoauth"):
                    delegation_findings.append((name, "TrustedToAuth", True))

                # 1. Check Aces
                for ace in item.get("Aces", []):
                    right = ace.get("RightName")
                    source = ace.get("PrincipalSID")
                    target = obj_id
                    edge_counts[right] += 1
                    if len(edge_examples[right]) < 3:
                        edge_examples[right].append({
                            "source": source,
                            "source_type": ace.get("PrincipalType"),
                            "target": target,
                            "target_type": obj_type,
                            "inherited": ace.get("IsInherited")
                        })
                        
                # 2. Check Members in Groups
                for m in item.get("Members", []):
                    m_id = m.get("ObjectIdentifier")
                    edge_counts["MemberOf"] += 1
                    if len(edge_examples["MemberOf"]) < 3:
                        edge_examples["MemberOf"].append({
                            "source": m_id,
                            "source_type": m.get("ObjectType"),
                            "target": obj_id,
                            "target_type": "Group"
                        })
                        
                # 3. Check PrimaryGroupSID
                if item.get("PrimaryGroupSID"):
                    pg_id = item.get("PrimaryGroupSID")
                    edge_counts["PrimaryGroupMemberOf"] += 1
                    
                # 4. Check LocalAdmins, RemoteDesktopUsers, DcomUsers, PSRemoteUsers in Computers
                for admin in item.get("LocalAdmins", []):
                    edge_counts["AdminTo"] += 1
                for rdp in item.get("RemoteDesktopUsers", []):
                    edge_counts["CanRDP"] += 1
                for dcom in item.get("DcomUsers", []):
                    edge_counts["ExecuteDCOM"] += 1
                for ps in item.get("PSRemoteUsers", []):
                    edge_counts["CanPSRemote"] += 1
                    
                # 5. Check Sessions
                for sess in item.get("Sessions", []):
                    edge_counts["HasSession"] += 1
                    
                # 6. Check Links in Domains / OUs (GPLink)
                for link in item.get("Links", []):
                    edge_counts["GPLink"] += 1
                    if len(edge_examples["GPLink"]) < 3:
                        edge_examples["GPLink"].append({
                            "source": obj_id,
                            "target": link.get("Guid") or link.get("ObjectIdentifier"),
                            "enforced": link.get("IsEnforced")
                        })
                        
                # 7. Check ChildObjects / Containers
                for child in item.get("ChildObjects", []):
                    edge_counts["Contains"] += 1

    print("\n--- DELEGATION FINDINGS ---")
    for d in delegation_findings:
        print(f"  {d[0]}: {d[1]} -> {d[2]}")
        
    print("\n--- ALL EDGE TYPES FOUND & COUNTS ---")
    for edge_name, count in edge_counts.most_common():
        print(f"  {edge_name:30s}: {count:5d}")
        
    print("\n--- SAMPLE EXAMPLES FOR NOTABLE EDGES ---")
    for edge_name in ["MemberOf", "AdminTo", "CanRDP", "CanPSRemote", "ExecuteDCOM", "GPLink", "WriteDacl", "GenericWrite", "GenericAll", "Owns"]:
        if edge_name in edge_examples:
            print(f"\nEdge: {edge_name}")
            for ex in edge_examples[edge_name]:
                src_name = objects_by_id.get(ex.get('source'), {}).get('name', ex.get('source'))
                tgt_name = objects_by_id.get(ex.get('target'), {}).get('name', ex.get('target'))
                print(f"  {src_name} -> {tgt_name} (details: {ex})")

if __name__ == "__main__":
    inspect_all()
