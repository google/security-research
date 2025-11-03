SELECT
    source_uri,
    source_function_start_line,
    source_function_end_line,
    source_function_names,
    group_concat(SUBSTR(syscall, length('__do_sys_') + 1), ' ') syscalls
FROM edges_with_functions_per_syscall
WHERE
    rule_id = 'callgraph-all'
    AND target_uri = $file_path
    AND (
        target_startLine = $start_line
        OR target_function_end_line = $end_line
    )
GROUP BY
    source_uri,
    source_function_start_line,
    source_function_end_line,
    source_function_names;