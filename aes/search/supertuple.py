import numpy as np

class SuperTuple:
    #de la forme :  vecteur tel que x = -x
    def __init__(self, data):
        self.data = tuple(data)


    def to_array(self):
        return np.array(list(self.data))
    
    def negate(self):
        return tuple([-1 * x for x in self.data])
    
    def __str__(self):
        return str(self.data)
    
    def __repr__(self):
        return str(self.data)
    

    def __hash__(self):
        return hash(self.data) ^ hash(self.negate())  #workaround to make sure that the negation is the same constraint
    
    def __eq__(self, other):
        if not isinstance(other, SuperTuple):
            # only equality tests to other `structure` instances are supported
            return NotImplemented
        return self.data == other.data or self.negate() == other.data
    
    def __getitem__(self, key):
        return self.data[key]