from supertuple import SuperTuple
import numpy as np
from utils import *
from itertools import product
import pickle


# Turning a function into a set of constraints

def partition_input(f, l):
    part_true = set()
    part_false = set()
    for t in product(range(2), repeat=l):
        if f(t):
            part_true.add(bool_vector_to_int(t))
        else:
            part_false.add(bool_vector_to_int(t))
    return part_false, part_true



def create_set_constraints(f ,l):
    f, t = partition_input(f, l)
    constraints = {i : set() for i in range(l)} #the constraints are organized by index of depth where they will be used
    for x, y in product(f, t):
        x_b = tuple(int_to_bool_vector(x, padding=l))
        y_b = tuple(int_to_bool_vector(y, padding=l))
        c = diff_tuple(x_b, y_b)
        #let's store it in the appropriate depth
        i  = l - 1
        while not abs(c[i]):
            i -= 1
        constraints[i].add(SuperTuple(c[:i + 1]))
    # pretty_print(constraints)
    return constraints


def pretty_print(constraints):
    l = len(list(constraints.keys()))
    m = []
    for i, cons_i in constraints.items():
        for c in cons_i:
            m.append(list(c) + [0 for _ in range(l - i - 1)])
    print(m)
    print(np.array(m))


# core searching algorithm


    
def build_next_set(inputs, constraints, p, symmetries=[]):
    current_index = len(inputs)
    filtered_constraints = constraints[current_index]
    forbidden_values = set()
    #pruning thanks to symmetries
    for input_symmetric in neighbors_in_tuples(symmetries, current_index):
        for x in range(inputs[input_symmetric]):
            forbidden_values.add(x)

    # pivot
    for c in filtered_constraints:
        comb_lin = [-1 * c[-1] * x for x in c[:-1]]
        forbidden_values.add(sum([ci * qi for ci, qi in zip(comb_lin, inputs)]) % p)
        if len(forbidden_values) == p:
            break
    # print(f"Debug: c = {len(filtered_constraints)}; actual cuts : {len(forbidden_values) - 1};expected : {p-1-esperance_branches_survivantes(p, len(filtered_constraints))}")
    # print(f"Debug : {forbidden_values}")
    return (x for x in range(p) if x not in forbidden_values)




def search(inputs, constraints, p, l, symmetries=[]):
    if len(inputs) == l:
            return inputs
    else:
        possibles = build_next_set(inputs, constraints, p, symmetries)
        for x in possibles:
            inputs = inputs + [x]
            result = search(inputs, constraints, p, l, symmetries)
            if result:
                return result
            else:
                inputs.pop(-1)
        return False



def full_search(f, l, max_p=31, symmetries=[]):
    constraints = create_set_constraints(f, l)
    for p in range(3, max_p, 2):
        print(f"p:{p}")
        result = search([1], constraints, p, l, symmetries)
        if result:
            return result, p
        



## Function to check the validity of the results


def get_final_encoding(f, l, q, p):
    V = np.array(list(product(range(2), repeat=l)))
    r = np.dot(V, q) % p
    F, T = set(), set()
    for vi, ri in zip(V, r):
        if f(vi):
            T.add(ri)
        else:
            F.add(ri)
    assert F.isdisjoint(T), f"{F} not disjoint of {T}"
    return F, T


