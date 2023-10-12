
def int_to_bool_vector(int, padding=0):
    vec = []
    while int:
        vec = [int % 2] + vec
        int = int >> 1
    return [0 for _ in range(padding - len(vec))] + vec

def bool_vector_to_int(vec):
    vec = list(vec)
    vec.reverse()
    return sum([x * 2 ** l for l, x in enumerate(vec)])


def diff_tuple(a, b):
    return tuple([x_a - x_b for x_a, x_b in zip(a, b)])


def neighbors_in_tuples(data, target):
    #data is a list of tuple. checks if target is a non-first element of some tuples, and if so, returns the preceding element of these tuples
    filter =  [x for x in data if target in x[1:]]
    neighbors = []
    for x in filter:
        neighbors.append(x[x.index(target) - 1])
    return neighbors