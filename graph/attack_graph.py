# graph/attack_graph.py
import networkx as nx
from typing import Dict, Any, List
from ingestion.schemas import NormalizedEvent


def build_attack_graph(incident: Dict[str, Any]) -> nx.DiGraph:
    """
    Build attack graph from incident.
    
    Nodes: entity, ip, incident pattern
    Edges: login attempts, incident relation
    """
    G = nx.DiGraph()
    
    entity = incident["entity"]
    pattern = incident["pattern"]
    
    # Add entity node
    G.add_node(entity, node_type="entity")
    
    # Add IP and event edges
    for event in incident["events"]:
        src_ip = event.metadata.get("src_ip")
        if src_ip:
            G.add_node(src_ip, node_type="ip")
            G.add_edge(src_ip, entity, event_type=event.event_type, timestamp=event.timestamp.isoformat())
    
    # Add incident pattern node
    G.add_node(pattern, node_type="pattern", kill_chain_stage=incident["kill_chain_stage"])
    
    # Link entity to incident pattern
    G.add_edge(entity, pattern, relation="observed_in")
    
    return G


def get_attack_paths(G: nx.DiGraph, source: str = None) -> List[List[str]]:
    """Get all attack paths from source node or all paths."""
    if source and source not in G:
        return []
    
    paths = []
    
    if source:
        # Get all paths from source
        for target in G.nodes():
            if target != source:
                try:
                    for path in nx.all_simple_paths(G, source, target):
                        paths.append(path)
                except nx.NetworkXNoPath:
                    pass
    else:
        # Get all simple paths in the graph
        nodes = list(G.nodes())
        for i, source_node in enumerate(nodes):
            for target_node in nodes[i+1:]:
                try:
                    for path in nx.all_simple_paths(G, source_node, target_node):
                        paths.append(path)
                except nx.NetworkXNoPath:
                    pass
    
    return paths


def print_attack_graph(G: nx.DiGraph, incident_name: str = ""):
    """Pretty print attack graph."""
    if incident_name:
        print(f"\n[ATTACK GRAPH] {incident_name}")
        print("=" * 60)
    
    print(f"Nodes ({G.number_of_nodes()}):")
    for node, attrs in G.nodes(data=True):
        node_type = attrs.get("node_type", "unknown")
        print(f"  - {node} (type: {node_type})")
    
    print(f"\nEdges ({G.number_of_edges()}):")
    for source, target, attrs in G.edges(data=True):
        event = attrs.get("event_type", attrs.get("relation", ""))
        print(f"  - {source} → {target} [{event}]")
