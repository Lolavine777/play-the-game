import json
from pathlib import Path

def inspect_advanced():
    data_dir = Path("data/raw/NORTH")
    
    # Load all objects mapping
    objects = {}
    for f in data_dir.glob("*.json"):
        with open(f) as fp:
            data = json.load(fp)
            for item in data.get("data", []):
                oid = item.get("ObjectIdentifier")
                name = item.get("Properties", {}).get("name") or oid
                otype = item.get("Properties", {}).get("type") or data.get("meta", {}).get("type")
                objects[oid] = {"name": name, "type": otype}
                
    print("=== INSPECTING DCSYNC RIGHTS (GetChanges / GetChangesAll) ===")
    for f in data_dir.glob("*domains*.json"):
        with open(f) as fp:
            data = json.load(fp)
            for item in data.get("data", []):
                for ace in item.get("Aces", []):
                    r = ace.get("RightName")
                    if "GetChanges" in r:
                        src_id = ace.get("PrincipalSID")
                        src = objects.get(src_id, {}).get("name", src_id)
                        print(f"  {src} ({ace.get('PrincipalType')}) -> {r} on Domain")

    print("\n=== INSPECTING AddKeyCredentialLink ===")
    for f in data_dir.glob("*.json"):
        with open(f) as fp:
            data = json.load(fp)
            for item in data.get("data", []):
                target_id = item.get("ObjectIdentifier")
                target_name = item.get("Properties", {}).get("name", target_id)
                for ace in item.get("Aces", []):
                    if ace.get("RightName") == "AddKeyCredentialLink":
                        src_id = ace.get("PrincipalSID")
                        src = objects.get(src_id, {}).get("name", src_id)
                        print(f"  {src} -> AddKeyCredentialLink on {target_name} ({objects.get(target_id, {}).get('type')})")

    print("\n=== INSPECTING AD CS TEMPLATES (Vulnerable ESC?) ===")
    for f in data_dir.glob("*certtemplates*.json"):
        with open(f) as fp:
            data = json.load(fp)
            for item in data.get("data", []):
                props = item.get("Properties", {})
                name = props.get("name")
                # Check ESC1: client auth + enrolleesuppliessubject
                enrollee_supplies = props.get("enrolleesuppliessubject", False)
                client_auth = props.get("clientauthentication", False)
                requires_manager_approval = props.get("requiresmanagerapproval", False)
                if client_auth or enrollee_supplies:
                    print(f"Template: {name} | ClientAuth: {client_auth} | EnrolleeSuppliesSubject: {enrollee_supplies} | ManagerApproval: {requires_manager_approval}")
                    for ace in item.get("Aces", []):
                        if ace.get("RightName") in ["Enroll", "GenericAll", "WriteDacl"]:
                            src_id = ace.get("PrincipalSID")
                            src = objects.get(src_id, {}).get("name", src_id)
                            print(f"   -> ACE: {src} has {ace.get('RightName')}")

inspect_advanced()
