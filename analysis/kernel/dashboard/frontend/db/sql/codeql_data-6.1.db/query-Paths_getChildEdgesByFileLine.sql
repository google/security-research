SELECT DISTINCT
    source_message,
    target_startLine,
    target_uri,
    target_function_end_line
FROM edges_with_functions
WHERE
    rule_id = 'callgraph-all'
    AND source_uri = $file_path
    AND source_startLine > $start_line
    AND source_startLine < $end_line;