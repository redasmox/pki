from collections import defaultdict, deque

class OFSM:
    def __init__(self, states, initial_state, inputs, outputs, transitions):
        self.states = states
        self.initial_state = initial_state
        self.inputs = inputs
        self.outputs = outputs
        self.transitions = transitions  # transitions[(s, x)] = {y: s'}

    def get_next_state(self, s, x, y):
        return self.transitions.get((s, x), {}).get(y, None)

class UIONode:
    def __init__(self, input_seq, output_seq, initial_to_current):
        self.input_seq = input_seq
        self.output_seq = output_seq
        self.initial_to_current = initial_to_current  # dict {s_initial: s_current}
        self.depth = len(input_seq)

    @property
    def initial_states(self):
        return set(self.initial_to_current.keys())

    @property
    def current_states(self):
        return set(self.initial_to_current.values())

    def __repr__(self):
        return f"UIONode(in={self.input_seq}, out={self.output_seq}, init2curr={self.initial_to_current})"

def find_uio_sequences(ofsm, max_length):
    root = UIONode([], [], {s: s for s in ofsm.states})
    uio_sequences = {s: None for s in ofsm.states}
    nodes_by_depth = defaultdict(list)
    nodes_by_depth[0].append(root)
    visited = set()

    for current_depth in range(max_length + 1):
        current_level_nodes = nodes_by_depth.get(current_depth, [])
        next_level_nodes = []

        for node in current_level_nodes:
            node_key = (tuple(node.input_seq), tuple(node.output_seq))
            if node_key in visited:
                continue
            visited.add(node_key)

            if current_depth >= max_length:
                continue

            for x in ofsm.inputs:
                y_groups = defaultdict(dict)
                for s_initial, s_current in node.initial_to_current.items():
                    possible_ys = ofsm.transitions.get((s_current, x), {})
                    for y, s_next in possible_ys.items():
                        y_groups[y][s_initial] = s_next

                for y, group in y_groups.items():
                    new_input_seq = node.input_seq + [x]
                    new_output_seq = node.output_seq + [y]
                    new_node = UIONode(new_input_seq, new_output_seq, group)
                    new_node_key = (tuple(new_input_seq), tuple(new_output_seq))
                    if new_node_key not in visited:
                        nodes_by_depth[current_depth + 1].append(new_node)

        input_seq_nodes = defaultdict(list)
        for node in current_level_nodes:
            input_seq_nodes[tuple(node.input_seq)].append(node)

        for input_seq, nodes in input_seq_nodes.items():
            for s in ofsm.states:
                if uio_sequences[s] is not None:
                    continue
                s_distinguished = True
                s_found = False
                for node in nodes:
                    if s in node.initial_states:
                        s_found = True
                        if len(node.initial_states) != 1:
                            s_distinguished = False
                            break
                if s_found and s_distinguished:
                    uio_sequences[s] = list(input_seq)

    return uio_sequences

# Example usage:
if __name__ == "__main__":
    # Define an OFSM (modify according to your FSM)
    transitions = {
        ('s1', 'a'): {'z': 's2'},
        ('s2', 'c'): {'x': 's3'},
        ('s3', 'b'): {'z': 's3'},
        ('s3', 'a'): {'z': 's4'},
        ('s4', 'b'): {'t': 's1'},
        ('s1', 'b'): {'t': 's3'},
    }
    ofsm = OFSM(
        states=['s1', 's2','s3', 's4'],
        initial_state='s0',
        inputs=['a', 'b','c'],
        outputs=['t', 'x','z'],
        transitions=transitions
    )

    max_length = 3
    uio_sequences = find_uio_sequences(ofsm, max_length)
    print("UIO Sequences:")
    for state, seq in uio_sequences.items():
        print(f"{state}: {seq if seq else 'Not found'}")