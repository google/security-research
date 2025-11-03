WITH RECURSIVE traverse_callgraph AS (
    SELECT
        -1 depth,
        $file_path caller_uri,
        $end_line caller_endLine,
        null callee_uri,
        null callee_endLine
    UNION ALL
    SELECT
        depth + 1 depth,
        source_uri caller_uri,
        source_function_end_line caller_endLine,
        target_uri callee_uri,
        target_function_end_line callee_endLine
    FROM
        edges_with_functions_per_syscall
    JOIN
        traverse_callgraph on (
            syscall = $syscall
            AND target_uri = caller_uri
            AND target_function_end_line = caller_endLine
        )
    WHERE
        depth < $depth
    ORDER BY depth ASC
    LIMIT $limit
    OFFSET $offset
)
SELECT
    caller_uri,
    caller_endLine,
    callee_uri,
    callee_endLine
FROM traverse_callgraph WHERE depth BETWEEN 0 AND $depth;