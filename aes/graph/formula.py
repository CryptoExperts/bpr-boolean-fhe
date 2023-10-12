# Fonction qui permet d'extraire la fonction booléenne produisant un noeud particulier, pas vraiment d'usage dans le framework général
import networkx as nx
from circuit import creation_aes



AES = creation_aes()

def create_formula_from_node(circuit, node):
    if nx.get_node_attributes(circuit, "type")[node] == "input":
        return node
    
    op_node = next(circuit.predecessors(node))
    op = AES.nodes[op_node]["label"]
    p1, p2 = list(circuit.predecessors(op_node))
    return f"({create_formula_from_node(circuit, p1)} {op} {create_formula_from_node(circuit, p2)})"

