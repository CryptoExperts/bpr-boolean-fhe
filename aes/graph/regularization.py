import networkx as nx

def remove_dummy_nodes(circuit_in):
    #remove all nodes with only one child and one parent
    circuit = circuit_in.copy()
    nodes_to_remove = []
    for node in circuit.nodes:
        pred = list(circuit.predecessors(node))
        child = list(circuit.successors(node))
        if len(pred) == 1 and len(child) == 1:
            nodes_to_remove.append(node)
            circuit.add_edge(pred[0], child[0])
    circuit.remove_nodes_from(nodes_to_remove)
    return circuit


def duplicate_input_nodes(circuit_in):
    circuit = circuit_in.copy()
    #duplicates all input nodes
    nodes_to_remove = []
    new_nodes = []
    new_edges = []
    for node, data_node in circuit.nodes.items():
        if data_node["type"] == "input":
            successors = list(circuit.successors(node))
            if len(successors) > 1:
                nodes_to_remove.append(node)
                for i, s in enumerate(successors):
                    new_nodes.append(f"{node}_{i}")
                    new_edges.append((f"{node}_{i}", s))
    circuit.remove_nodes_from(nodes_to_remove)
    for node in new_nodes:
        circuit.add_node(node, label=node.split("_")[0], type="input")    
    circuit.add_edges_from(new_edges)
    return circuit


def create_multi_input_nodes(circuit):
    only_xor = nx.Graph(circuit.subgraph([n for n, d in circuit.nodes.items() if d["label"] == "^"]))
    for comp in nx.connected_components(only_xor):
        if len(comp) > 1:
            nodes = sorted(comp)
            for node in nodes[1:]:
                circuit = nx.contracted_nodes(circuit, nodes[0], node, self_loops=False)
    return circuit





def regularize_circuit(circuit):
    circuit = remove_dummy_nodes(circuit)
    circuit = duplicate_input_nodes(circuit)
    circuit = create_multi_input_nodes(circuit)
    return circuit