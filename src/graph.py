from random import choice, randrange, shuffle
from uuid import uuid4


class Node:
    def __init__(self, value):
        self.value = value

        self.left = None
        self.right = None
        self.name = 'n' + str(uuid4()).replace('-', '')


nodes = []

# Create a node for each instruction (ignoring comments and blank lines).
with open('secret.asm', 'r') as assembly:
    for instruction in assembly.readlines():
        instruction = instruction.split(';')[0].strip()
        if instruction != '':
            node = Node(instruction)

            if len(nodes) == 0:
                node.name = 'start'
            else:
                # Set the previous node's left or right (random) to the current node.
                if choice((True, False,)):
                    nodes[-1].left = node
                else:
                    nodes[-1].right = node

            nodes.append(node)


INTERCHANGABLES = ('mov', 'add', 'sub', 'cmp')
REGISTER_BS = ('al', 'ah', 'bl', 'bh', 'cl', 'ch', 'dl', 'dh')
REGISTER_WS = ('ax', 'bx', 'cx', 'dx', 'di', 'si')
REGISTER_DS = ('eax', 'ebx', 'ecx', 'edx', 'edi', 'esi')

kill_nodes = []

KILL_PATTERNS = (
    '{interchangable}     {register_b}, byte [{illegal_address}]',
    '{interchangable}     byte [{illegal_address}], {register_b}',
    '{interchangable}     {register_w}, word [{illegal_address}]',
    '{interchangable}     word [{illegal_address}], {register_w}',
    '{interchangable}     {register_d}, dword [{illegal_address}]',
    '{interchangable}     dword [{illegal_address}], {register_d}',
)

fill_nodes = []
FILL_PATTERNS = (
    'inc     {register}',
    'dec     {register}',
    '{interchangable}     {register}, {byte}',
)

for _ in range(232):
    # Kill nodes hold instructions causing the program to segfault.
    kill_nodes.append(Node(choice(KILL_PATTERNS).format(
        byte=randrange(0, 256),
        illegal_address=randrange(0x0, 0x08048000),
        interchangable=choice(INTERCHANGABLES),
        register=choice(REGISTER_BS+REGISTER_WS+REGISTER_DS),
        register_b=choice(REGISTER_BS),
        register_w=choice(REGISTER_WS),
        register_d=choice(REGISTER_DS),
    )))
    # Fill nodes do nothing.
    fill_nodes.append(Node(choice(FILL_PATTERNS).format(
        byte=randrange(0, 256),
        illegal_address=randrange(0x0, 0x08048000),
        interchangable=choice(INTERCHANGABLES),
        register=choice(REGISTER_BS+REGISTER_WS+REGISTER_DS),
        register_b=choice(REGISTER_BS),
        register_w=choice(REGISTER_WS),
        register_d=choice(REGISTER_DS),
    )))


# Every fill node should have children of either fill or kill nodes. There should be no loops.
for fill_node_index, fill_node_value in enumerate(fill_nodes):
    fill_node_value.left = choice(fill_nodes[:fill_node_index]+kill_nodes)
    fill_node_value.right = choice(fill_nodes[:fill_node_index]+kill_nodes)
    nodes.append(fill_node_value)

for kill_node in kill_nodes:
    nodes.append(kill_node)

# Assigning any unpopulated children.
for node in nodes:
    if node.left is None:
        if node in kill_nodes:
            node.left = choice(nodes)
        else:
            node.left = choice(fill_nodes)
    if node.right is None:
        if node in kill_nodes:
            node.right = choice(nodes)
        else:
            node.right = choice(fill_nodes)

shuffle(nodes)

# Writing the nodes to an asm file.
with open('graph.asm', 'w') as f:
    for node in nodes:
        f.write(f'{node.name}:\n')
        f.write(f'    dd      {node.left.name}\n')
        f.write(f'    dd      {node.right.name}\n')
        f.write(f'    {node.value}\n')
        f.write(f'    ret\n\n')
