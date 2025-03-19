# Importations nécessaires
from collections import defaultdict, deque  

# Classe représentant une Machine à États Finis 
class OFSM:
    def __init__(self, states, initial_state, inputs, outputs, transitions):
        # Initialise la machine avec ses composants
        self.states = states                # Liste des états (ex: ['s1', 's2', ...])
        self.initial_state = initial_state  # État initial (ex: 's1')
        self.inputs = inputs                # Liste des entrées possibles (ex: ['a', 'b'])
        self.outputs = outputs              # Liste des sorties possibles (ex: ['x', 'y'])
        self.transitions = transitions      # Dictionnaire des transitions: {(état, entrée): {sortie: état_suivant}}

    def get_next_state(self, s, x, y):
        """Retourne l'état suivant pour un état `s`, une entrée `x` et une sortie `y`."""
        return self.transitions.get((s, x), {}).get(y, None)  # Retourne None si non trouvé

# Classe représentant un nœud dans l'arbre de recherche UIO
class UIONode:
    def __init__(self, input_seq, output_seq, initial_to_current):
        self.input_seq = input_seq          # Séquence d'entrées (ex: ['a', 'b'])
        self.output_seq = output_seq        # Séquence de sorties (ex: ['z', 't'])
        self.initial_to_current = initial_to_current  # Dictionnaire {état_initial: état_actuel}
        self.depth = len(input_seq)        # Longueur de la séquence d'entrées

    @property
    def initial_states(self):
        """Retourne les états initiaux associés à ce nœud."""
        return set(self.initial_to_current.keys())

    @property
    def current_states(self):
        """Retourne les états actuels après application de la séquence."""
        return set(self.initial_to_current.values())

    def __repr__(self):
        """Représentation lisible du nœud (pour débogage)."""
        return f"UIONode(in={self.input_seq}, out={self.output_seq}, init2curr={self.initial_to_current})"

# Fonction principale pour trouver les séquences UIO
def find_uio_sequences(ofsm, max_length):
    # Initialisation du nœud racine (séquence vide)
    root = UIONode([], [], {s: s for s in ofsm.states})  # Tous les états initiaux mappés à eux-mêmes
    uio_sequences = {s: None for s in ofsm.states}        # Dictionnaire pour stocker les résultats
    nodes_by_depth = defaultdict(list)                    # Nœuds regroupés par profondeur (longueur de séquence)
    nodes_by_depth[0].append(root)                        # Ajoute le nœud racine
    visited = set()                                        # Séquence déjà traitées (pour éviter les doublons)

    # Exploration en largeur jusqu'à max_length inclus
    for current_depth in range(max_length + 1):
        current_level_nodes = nodes_by_depth.get(current_depth, [])  # Nœuds actuels à cette profondeur
        next_level_nodes = []                                         # Nœuds pour la profondeur suivante

        # Traitement de chaque nœud à la profondeur actuelle
        for node in current_level_nodes:
            # Clé unique pour éviter les doublons 
            node_key = (tuple(node.input_seq), tuple(node.output_seq))
            if node_key in visited:
                continue  # Ignore les nœuds déjà visités
            visited.add(node_key)  # Marque comme visité

            # Arrête l'expansion si la profondeur maximale est atteinte
            if current_depth >= max_length:
                continue

            # Génère toutes les transitions possibles pour chaque entrée
            for x in ofsm.inputs:
                y_groups = defaultdict(dict)  # Groupe les transitions par sortie y
                for s_initial, s_current in node.initial_to_current.items():
                    # Récupère les transitions possibles pour l'état courant et l'entrée x
                    possible_ys = ofsm.transitions.get((s_current, x), {})
                    for y, s_next in possible_ys.items():
                        y_groups[y][s_initial] = s_next  # Regroupe par sortie y

                # Crée de nouveaux nœuds pour chaque groupe de sortie
                for y, group in y_groups.items():
                    new_input_seq = node.input_seq + [x]
                    new_output_seq = node.output_seq + [y]
                    new_node = UIONode(new_input_seq, new_output_seq, group)
                    new_node_key = (tuple(new_input_seq), tuple(new_output_seq))
                    if new_node_key not in visited:
                        nodes_by_depth[current_depth + 1].append(new_node)  # Ajoute au niveau suivant

        # Regroupe les nœuds par séquence d'entrée pour vérifier les UIO
        input_seq_nodes = defaultdict(list)
        for node in current_level_nodes:
            input_seq_nodes[tuple(node.input_seq)].append(node)  # Clé = séquence d'entrée

        # Vérifie si une séquence d'entrée est UIO pour un état
        for input_seq, nodes in input_seq_nodes.items():
            for s in ofsm.states:
                if uio_sequences[s] is not None:
                    continue  # UIO déjà trouvé pour cet état
                s_distinguished = True
                s_found = False
                for node in nodes:
                    if s in node.initial_states:
                        s_found = True
                        # Vérifie si s est le seul état initial dans ce nœud
                        if len(node.initial_states) != 1:
                            s_distinguished = False
                            break
                # Si s est unique pour cette séquence d'entrée, c'est un UIO
                if s_found and s_distinguished:
                    uio_sequences[s] = list(input_seq)  # Enregistre la séquence UIO

    return uio_sequences


if __name__ == "__main__":
    
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
        initial_state='s1',
        inputs=['a', 'b','c'],
        outputs=['t', 'x','z'],
        transitions=transitions
    )

    max_length = 3  
    uio_sequences = find_uio_sequences(ofsm, max_length)
    print("UIO Sequences:")
    for state, seq in uio_sequences.items():
        print(f"{state}: {seq if seq else 'Not found'}")  
