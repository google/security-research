SELECT DISTINCT
    'indirect call' edge_type,
    field identifier,
    target_file file_path,
    target_start start_line,
    target_end end_line
FROM
    ops_targets
WHERE
    exprcall_file = $file_path AND
    exprcall_line = $start_line
UNION
SELECT DISTINCT
    'direct call' edge_type,
    source_message identifier,
    target_uri file_path,
    target_startLine start_line,
    target_function_end_line end_line
FROM edges_with_functions
WHERE
    rule_id = 'callgraph-all' AND
    source_uri = $file_path AND
    source_startLine = $start_line
UNION
SELECT DISTINCT
    'macro call' edge_type,
    macro_name identifier,
    macro_file_path file_path,
    macro_start_line start_line,
    macro_end_line end_line
FROM macro_edges
WHERE
    edge_file_path = $file_path AND
    edge_start_line = $start_line;