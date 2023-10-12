import networkx as nx
from graph.aes import S_BOX

################################
#  Creation of a graph from a set of operations. The format of the code is one instruction per line
################################

def parse_operation(operation):
    #parsing operation
    res, eq2 = operation.split(" = ")
    ter1, op, ter2 = eq2.split(" ")
    return (res, ter1, op, ter2)


# Function AES-specific : see if it can be made more generic
def add_inputs(circuit):
    circuit.add_node('x7', label='x7', type="input")
    for i in range(1, 22):
        circuit.add_node(f"y{i}", label=f"y{i}", type="input")


def add_operation(circuit, operation, counter_and, counter_xor):
    res, ter1, op, ter2 = parse_operation(operation)

    counter_op = counter_and if op == '&' else counter_xor
    id_op = f"({op}, {counter_op})"
    circuit.add_node(id_op, label = op, type="boolean")
    circuit.add_edge(ter1, id_op)
    circuit.add_edge(ter2, id_op)
    
    circuit.add_node(res, label=res, type="intermediary")
    circuit.add_edge(id_op, res)

    if op == '&':
        counter_and += 1
    elif op == '^':
        counter_xor +=1
    else:
        raise ValueError
    
    return counter_and, counter_xor



def creation_aes():
    circuit = nx.DiGraph()
    add_inputs(circuit)

    counter_and = 0
    counter_xor = 0
    for line in S_BOX.split("\n"):
        operation = line.strip()
        counter_and, counter_xor = add_operation(circuit, operation, counter_and, counter_xor)

    return circuit


########################################
# Display function
########################################


from IPython.display import SVG, display
import os

def plot_circuit(circuit, output_name=None, print=False):
    graphviz_object = nx.nx_agraph.to_agraph(circuit)
    graphviz_object.node_attr["style"] = "filled"

    for node in graphviz_object.iternodes():
        node.attr["label"] = circuit.nodes[node]["label"]
        match circuit.nodes[node]["type"]:
            case "boolean":
                node.attr["shape"] = "square"
                match circuit.nodes[node]["label"]:
                    case '^':
                        node.attr["fillcolor"] = "#FFFFFF"
                    case '&':
                        node.attr["fillcolor"] = "#555555"
            case "input":
                node.attr["fillcolor"] = "#90EE90"
            case "intermediary":
                if "z" in circuit.nodes[node]["label"]: #ugly workaround to emphasize output nodes
                    node.attr["fillcolor"] = "#FCF55F"
                else:
                    node.attr["fillcolor"] = "#ffcccb"
        #multi output 
        if len(list(circuit.successors(node))) > 1 and circuit.nodes[node]["type"] == "intermediary":
            node.attr["fillcolor"] = "#ff4444"

    graphviz_object.layout('dot')
    if output_name:
        graphviz_object.draw(f'plots/{output_name}.svg')
        
    if print and output_name:
        display(SVG(f'plots/{output_name}.svg'))
    
    elif print and not output_name:
        graphviz_object.draw('plots/placeholder.svg')
        display(SVG('plots/placeholder.svg'))
        os.remove('plots/placeholder.svg')


#########################################
# Subgraph generation
#########################################


# Util function to aggregate nodes belonging to the same subgraph

def collect_parents(circuit, current, stop_on_intermediary=False):
    predecessors = circuit.predecessors(current)
    for p in predecessors:
        yield p
        if stop_on_intermediary:
            if circuit.nodes[p]["type"] == "intermediary":
                continue
        yield from collect_parents(circuit, p, stop_on_intermediary)


# Creation of the graph generating a given node, until the inputs or not.

def create_subgraph_from_node(circuit, output, with_root=True, stop_on_intermediary=False):
    #create subgraph that leads to the production of the given output
    nodes = set(collect_parents(circuit, output, stop_on_intermediary))
    if with_root:
        nodes.add(output)
    return circuit.subgraph(nodes)




########################################
# Boolean evaluation in a circuit
#####################################


# Util function that find the elaves of a tree

def find_leaves(tree):
    return (node for node in tree.nodes if tree.in_degree(node) == 0)



#function to evaluate a subtree to produce the output `node` : the inputs must be formatted as a dict {node : value}

def evaluation_subtree(subtree, inputs, node):
    if node in inputs:
        return inputs[node]
    elif subtree.nodes[node]["type"] == "boolean":
        pred = list(subtree.predecessors(node))
        op = subtree.nodes[node]["label"]
        result = evaluation_subtree(subtree, inputs, pred[0])
        for p in pred[1:]:
            match op:
                case '&':
                    result = result &  evaluation_subtree(subtree, inputs, p)
                case '^':
                    result =  result ^  evaluation_subtree(subtree, inputs, p)
        return result
    elif subtree.nodes[node]["type"] == "intermediary":
        pred = list(subtree.predecessors(node))
        assert len(pred) == 1
        pred = pred[0]
        return evaluation_subtree(subtree, inputs, pred)



# Wrapper around the former function, but the inputs are formatted as a vector. Note that the order of the vector is the same as the one of the result of a call to find_leaves() on the subtree (new version of Python ensures the order of the dict)

def evaluation_subtree_from_vec(subtree, inputs, root):
    # perform a few sanity checks and format the dictionary of inputs
    leaves = list(find_leaves(subtree))
    assert len(inputs) == len(leaves)
    assert len(list(subtree.predecessors(root))) == 1
    starting_point = list(subtree.predecessors(root))[0]
    inputs_formatted = {n : i for n, i in zip(leaves, inputs)}
    return evaluation_subtree(subtree, inputs_formatted, starting_point)   


# Find symmetries within a circuit.

def find_symmetries(subtree):
    # Si deux entrées sont branchées sur la même porte, alors elles sont symétriques
    leaves = list(find_leaves(subtree))
    symmetries = {}
    for i, leaf in enumerate(leaves):
        if len(list(subtree.successors(leaf))) > 1:
            #pas de symétries si le noeud n'a pas d'enfant
            continue
        successor = list(subtree.successors(leaf))[0]
        if successor not in symmetries:
            symmetries[successor] = [i]
        else:
            symmetries[successor].append(i)
    return [sym for _, sym in symmetries.items() if len(sym) > 1]
