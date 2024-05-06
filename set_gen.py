from random import sample
from parameters import server_size, client_size, intersection_size

#set elements can be integers < order of the generator of the elliptic curve (192 bits integers if P192 is used); 'sample' works only for a maximum of 63 bits integers.
disjoint_union = sample(range(2 ** 20 - 1), server_size + client_size - intersection_size)

# First 'intersection_size' elements for the intersection
intersection = disjoint_union[:intersection_size]

# Next portion for the server's exclusive elements
server_exclusive = disjoint_union[intersection_size:intersection_size + (server_size - intersection_size)]

# Remaining elements for the client's exclusive elements
client_exclusive = disjoint_union[intersection_size + (server_size - intersection_size):]

# Combining to form full sets
server_set = intersection + server_exclusive
client_set = intersection + client_exclusive


f = open('server_set', 'w')
for item in server_set:
	f.write(str(item) + '\n')
f.close()

g = open('client_set', 'w')
for item in client_set:
	g.write(str(item) + '\n')
g.close()		

h = open('intersection', 'w')
for item in intersection:
	h.write(str(item) + '\n')
h.close()
