import json
import pandas as pd
import networkx as nx
from pathlib import Path

# Load weights contract
weights_df = pd.read_csv("data/processed/edge_weights_contract.csv")
weight_map = dict(zip(weights_df["EdgeType"], weights_df["Weight_MAUT"]))
# Default weight for any unlisted edge
default_weight = 2.50

def build_attack_graph():
    G = nx.DiGraph()
    data_dir = Path("data/raw/NORTH")
    
    # 1. Load basic objects
    for f in data_dir.glob("*.json"):
        with open(f, "r", encoding="utf-8") as fp:
            data = json.load(fp)
            for item in data.get("data", []):
                oid = item.get("ObjectIdentifier")
                name = item.get("Properties", {}).get("name") or oid
                otype = item.get("Properties", {}).get("type") or data.get("meta", {}).get("type")
                G.add_node(oid, name=name, type=otype)
                
                # Aces
                for ace in item.get("Aces", []):
                    src = ace.get("PrincipalSID")
                    right = ace.get("RightName")
                    w = weight_map.get(right, default_weight)
                    G.add_edge(src, oid, type=right, weight=w)
                    
                # Members
                for m in item.get("Members", []):
                    w = weight_map.get("MemberOf", 1.0)
                    G.add_edge(m.get("ObjectIdentifier"), oid, type="MemberOf", weight=w)
                    
                # PrimaryGroup
                if item.get("PrimaryGroupSID"):
                    w = weight_map.get("PrimaryGroupMemberOf", 1.0)
                    G.add_edge(oid, item.get("PrimaryGroupSID"), type="PrimaryGroupMemberOf", weight=w)
                    
                # RegistrySessions
                for s in item.get("RegistrySessions", {}).get("Results", []):
                    w = weight_map.get("HasSession", 3.55)
                    # When attacker controls Computer, they can compromise logged in User
                    G.add_edge(s.get("ComputerSID"), s.get("UserSID"), type="HasSession", weight=w)

    # 2. Add Domain & OU -> GPO Links & GPO -> Computer relationships
    # In Active Directory attack path:
    # If GPO is edited, it controls the computers in OUs/Domain it is linked to!
    # GPO -> Computer (via GPLink)
    for f in data_dir.glob("*domains*.json"):
        with open(f) as fp:
            for item in json.load(fp).get("data", []):
                domain_id = item.get("ObjectIdentifier")
                for link in item.get("Links", []):
                    gpo_guid = link.get("GUID")
                    # GPO applies to computers in this domain
                    w = weight_map.get("GPLink", 3.0)
                    # Attacker controlling GPO controls computers in Domain
                    for c_id, c_data in G.nodes(data=True):
                        if c_data.get("type") == "computers":
                            G.add_edge(gpo_guid, c_id, type="GPLink", weight=w)

    # 3. Add RemoteDesktopUsers group effect (CanRDP)
    # Built-in Remote Desktop Users group confers CanRDP to computers
    rdp_group_sid = "NORTH.SEVENKINGDOMS.LOCAL-S-1-5-32-555"
    w_rdp = weight_map.get("CanRDP", 2.4)
    for c_id, c_data in G.nodes(data=True):
        if c_data.get("type") == "computers":
            G.add_edge(rdp_group_sid, c_id, type="CanRDP", weight=w_rdp)

    # 4. Add AllowedToDelegate from CE dump
    ce_dir = Path("data/raw/NORTH_CE_PYTHON")
    for f in ce_dir.glob("*.json"):
        with open(f, "r", encoding="utf-8") as fp:
            data = json.load(fp)
            for item in data.get("data", []):
                oid = item.get("ObjectIdentifier")
                for atd in item.get("AllowedToDelegate", []):
                    target_id = atd.get("ObjectIdentifier")
                    w = weight_map.get("AllowedToDelegate", 2.3)
                    G.add_edge(oid, target_id, type="AllowedToDelegate", weight=w)

    # 5. DCSync effect: If node has GetChangesAll on Domain, it controls Domain Admins
    da_sid = "S-1-5-21-1252223512-2665318757-2669098637-512"
    for u, v, data in list(G.edges(data=True)):
        if data.get("type") == "GetChangesAll":
            w = weight_map.get("GetChangesAll", 2.65)
            G.add_edge(u, da_sid, type="DCSync", weight=w)

    # 6. Domain Controller takeover effect: If WINTERFELL is compromised, attacker has Domain Admin
    dc_sid = "S-1-5-21-1252223512-2665318757-2669098637-1001"
    G.add_edge(dc_sid, da_sid, type="AdminTo", weight=1.0)

    return G

G = build_attack_graph()
print(f"Graph constructed: {G.number_of_nodes()} nodes, {G.number_of_edges()} edges")

# Target
da_id = "S-1-5-21-1252223512-2665318757-2669098637-512"
winterfell_id = "S-1-5-21-1252223512-2665318757-2669098637-1001"

test_sources = [
    ("CASTELBLACK (Machine X)", "S-1-5-21-1252223512-2665318757-2669098637-1105"),
    ("SAMWELL.TARLY (User)", "S-1-5-21-1252223512-2665318757-2669098637-1119"),
    ("BRANDON.STARK (User)", "S-1-5-21-1252223512-2665318757-2669098637-1115"),
    ("JON.SNOW (User)", "S-1-5-21-1252223512-2665318757-2669098637-1118"),
]

for label, src_id in test_sources:
    print(f"\n=======================================================")
    print(f"ATTACK PATHS FROM: {label}")
    print(f"=======================================================")
    
    # 1. Shortest Path (Unweighted / BloodHound hop count)
    try:
        unweighted_path = nx.shortest_path(G, src_id, da_id)
        u_cost = sum(G[unweighted_path[i]][unweighted_path[i+1]]["weight"] for i in range(len(unweighted_path)-1))
        print(f"-> BloodHound Shortest (Hop Count = {len(unweighted_path)-1}, Total Cost W = {u_cost:.2f}):")
        for i in range(len(unweighted_path)-1):
            u, v = unweighted_path[i], unweighted_path[i+1]
            ed = G[u][v]
            print(f"   [{G.nodes[u].get('name')}] --({ed.get('type')}, w={ed.get('weight')})--> [{G.nodes[v].get('name')}]")
    except Exception as e:
        print("   No unweighted path:", e)

    # 2. Lowest Cost Path (Weighted Dijkstra)
    try:
        weighted_path = nx.dijkstra_path(G, src_id, da_id, weight="weight")
        w_cost = nx.dijkstra_path_length(G, src_id, da_id, weight="weight")
        print(f"-> Lowest-Cost Dijkstra (Hop Count = {len(weighted_path)-1}, Total Cost W = {w_cost:.2f}):")
        for i in range(len(weighted_path)-1):
            u, v = weighted_path[i], weighted_path[i+1]
            ed = G[u][v]
            print(f"   [{G.nodes[u].get('name')}] --({ed.get('type')}, w={ed.get('weight')})--> [{G.nodes[v].get('name')}]")
    except Exception as e:
        print("   No weighted path:", e)
