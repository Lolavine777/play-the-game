import json
from pathlib import Path
import networkx as nx

def build_graph():
    G = nx.DiGraph()
    
    # We will load both from NORTH and augment with delegation from NORTH_CE_PYTHON if needed
    data_dir = Path("data/raw/NORTH")
    
    # 1. Load users, computers, groups, gpos, ous, domains, containers, certtemplates
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
                    G.add_edge(src, oid, type=right, relation="ACE")
                    
                # Members
                for m in item.get("Members", []):
                    G.add_edge(m.get("ObjectIdentifier"), oid, type="MemberOf", relation="Group")
                    
                # PrimaryGroup
                if item.get("PrimaryGroupSID"):
                    G.add_edge(oid, item.get("PrimaryGroupSID"), type="MemberOf", relation="PrimaryGroup")
                    
                # RegistrySessions / Sessions
                for s in item.get("RegistrySessions", {}).get("Results", []):
                    # In attack graph: if attacker compromises Computer, they get User credential: Computer -> User
                    G.add_edge(s.get("ComputerSID"), s.get("UserSID"), type="HasSession", relation="Session")
                    
                # GPLinks: OU/Domain -> GPO applies to computer/user
                for link in item.get("Links", []):
                    guid = link.get("Guid")
                    if guid:
                        G.add_edge(guid, oid, type="GPLink", relation="GPO")

    # Also augment AllowedToDelegate from CE python if present
    ce_dir = Path("data/raw/NORTH_CE_PYTHON")
    for f in ce_dir.glob("*.json"):
        with open(f, "r", encoding="utf-8") as fp:
            data = json.load(fp)
            for item in data.get("data", []):
                oid = item.get("ObjectIdentifier")
                for atd in item.get("AllowedToDelegate", []):
                    target_id = atd.get("ObjectIdentifier")
                    G.add_edge(oid, target_id, type="AllowedToDelegate", relation="Delegation")

    return G

G = build_graph()
print(f"Graph built: {G.number_of_nodes()} nodes, {G.number_of_edges()} edges")

# Let's find IDs
names = {d["name"].upper(): n for n, d in G.nodes(data=True) if "name" in d}

def get_node_by_keyword(kw):
    for k, v in names.items():
        if kw.upper() in k:
            return v, k
    return None, None

castelblack_id, cb_name = get_node_by_keyword("CASTELBLACK")
winterfell_id, wf_name = get_node_by_keyword("WINTERFELL")
samwell_id, sam_name = get_node_by_keyword("SAMWELL.TARLY")
brandon_id, bran_name = get_node_by_keyword("BRANDON.STARK")
da_id, da_name = get_node_by_keyword("DOMAIN ADMINS@NORTH")
eddard_id, ed_name = get_node_by_keyword("EDDARD.STARK")

print(f"CASTELBLACK: {castelblack_id} ({cb_name})")
print(f"WINTERFELL: {winterfell_id} ({wf_name})")
print(f"SAMWELL: {samwell_id} ({sam_name})")
print(f"BRANDON: {brandon_id} ({bran_name})")
print(f"DOMAIN ADMINS: {da_id} ({da_name})")
print(f"EDDARD STARK: {eddard_id} ({ed_name})")

print("\n--- Shortest path CASTELBLACK -> WINTERFELL ---")
try:
    path = nx.shortest_path(G, castelblack_id, winterfell_id)
    print("Path found (length", len(path)-1, "):")
    for i in range(len(path)-1):
        u, v = path[i], path[i+1]
        edge_data = G.get_edge_data(u, v)
        print(f"  [{G.nodes[u].get('name')}] --({edge_data.get('type')})--> [{G.nodes[v].get('name')}]")
except Exception as e:
    print("No path:", e)

print("\n--- Shortest path SAMWELL.TARLY -> DOMAIN ADMINS ---")
try:
    path = nx.shortest_path(G, samwell_id, da_id)
    print("Path found (length", len(path)-1, "):")
    for i in range(len(path)-1):
        u, v = path[i], path[i+1]
        edge_data = G.get_edge_data(u, v)
        print(f"  [{G.nodes[u].get('name')}] --({edge_data.get('type')})--> [{G.nodes[v].get('name')}]")
except Exception as e:
    print("No path:", e)

print("\n--- Shortest path BRANDON.STARK -> DOMAIN ADMINS ---")
try:
    path = nx.shortest_path(G, brandon_id, da_id)
    print("Path found (length", len(path)-1, "):")
    for i in range(len(path)-1):
        u, v = path[i], path[i+1]
        edge_data = G.get_edge_data(u, v)
        print(f"  [{G.nodes[u].get('name')}] --({edge_data.get('type')})--> [{G.nodes[v].get('name')}]")
except Exception as e:
    print("No path:", e)
