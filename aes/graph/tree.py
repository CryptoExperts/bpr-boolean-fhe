# Idea of duplicating every nodes of a circuit to produce a pure tree. Not developed in the paper

import networkx as nx
from graph.circuit import create_subgraph_from_node



def duplicate_arbitrary_node(circuit_in, target):
    circuit = circuit_in.copy()
    tree_to_duplicate = nx.DiGraph(create_subgraph_from_node(circuit, target))
    predecessor = list(circuit.predecessors(target))
    assert len(predecessor) == 1
    predecessor = predecessor[0]
    successors = circuit.successors(target)
    circuit.remove_nodes_from(tree_to_duplicate.nodes)
    tree_to_duplicate.remove_node(target)
    for i, s in enumerate(successors):
        new_edges = [(f"{n1}_{i}", f"{n2}_{i}") for n1, n2 in tree_to_duplicate.edges]
        for node, data_node in tree_to_duplicate.nodes.items():
            circuit.add_node(f"{node}_{i}", label=data_node["label"], type=data_node["type"])
        circuit.add_edges_from(new_edges)
        circuit.add_edge(f"{predecessor}_{i}", s)
    return circuit



def duplicate_all_intermediary_nodes(circuit):
    nodes_to_duplicate = [node for node, data in circuit.nodes.items() if data["type"] == "intermediary" and 'z' not in node]
    while nodes_to_duplicate:
        circuit = duplicate_arbitrary_node(circuit, nodes_to_duplicate[0])
        nodes_to_duplicate = [node for node, data in circuit.nodes.items() if data["type"] == "intermediary" and 'z' not in node]
    return circuit
