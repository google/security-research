import sqlite3
from collections import defaultdict


def find_paths_to_function_recursive(db_file, function, max_depth=100):
    """
    Finds paths to $function recursively, finding edges
    by target message and filtering by rule_id.
    """

    conn = sqlite3.connect(db_file)
    cursor = conn.cursor()

    cursor.execute("SELECT id, message, uri, startLine FROM locations")
    locations = cursor.fetchall()

    # Create a dictionary to map location ID to (message, uri, startLine)
    location_map = defaultdict(set)
    for id, message, uri, startLine in locations:
        location_map[(message, uri, startLine)].add(id)

    # Find IDs corresponding to $function
    function_keys = [
        key for key, value in location_map.items() if key[0] == function
    ][0:1000]

    def preprocess_edges(cursor):
        cursor.execute(
            """
            SELECT e.source_location_id, e.target_location_id
            FROM edges AS e
            WHERE e.rule_id = 'callgraph-all'
            """
        )
        edges = {}
        for source_id, target_id in cursor.fetchall():
            if target_id not in edges:
                edges[target_id] = []
            edges[target_id].append(source_id)
        return edges

    edges = preprocess_edges(cursor)

    def find_edge_source(target_key):
        target_ids = location_map.get(target_key)
        if target_ids:
            for target_id in target_ids:
                source_ids = edges.get(target_id)
                if source_ids:
                    return source_ids
        return None

    paths = []  # To store all unique paths
    seen_paths = set()  # To keep track of visited paths

    def dfs_recursive(node_key, path, visited, depth):
        visited.add(node_key)
        path.append(node_key)

        neighbors = find_edge_source(node_key)

        if neighbors is not None:
            for neighbor_id in neighbors:
                for key, ids in location_map.items():
                    if neighbor_id in ids:
                        neighbor_key = key
                        break
                if (
                    neighbor_key
                    and depth < max_depth
                    and neighbor_key not in visited
                ):
                    dfs_recursive(
                        neighbor_key, path.copy(), visited.copy(), depth + 1
                    )
        else:
            path_tuple = tuple(path)
            if path_tuple not in seen_paths:
                seen_paths.add(path_tuple)
                paths.append(path.copy())

        path.pop()
        visited.remove(node_key)

    for start_key in function_keys:
        dfs_recursive(start_key, [], set(), 0)

    named_paths = []
    for path in paths:
        named_paths.append(path.copy())

    conn.close()
    return named_paths


if __name__ == "__main__":
    db_file = "codeql_data-6.1.db"
    paths = find_paths_to_function_recursive(db_file, "___sys_recvmsg")

    for path in paths:
        # Format the path
        formatted_path = " -> ".join(
            [f"{node[0]} ({node[1]}:{node[2]})" for node in path]
        )
        print(formatted_path)
        print()
