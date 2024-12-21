SELECT DISTINCT
    SUBSTR(syscall, length('__do_sys_') + 1) syscall
FROM syscall_node_with_functions
WHERE
    syscall IS NOT NULL AND
    function_file_path = $file_path AND
    (
        function_start_line = $start_line
        OR function_end_line = $end_line
    )
GROUP BY syscall