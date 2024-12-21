SELECT DISTINCT
    syscall,
    type condition_type,
    argument condition_argument,
    function_call_file_path,
    function_call_start_line,
    function_call_end_line
FROM
    syscall_condition_node_with_functions
WHERE
    function_file_path = $file_path AND (
        function_start_line = $start_line
    )
UNION
SELECT DISTINCT
    syscall,
    type condition_type,
    argument condition_argument,
    function_call_file_path,
    function_call_start_line,
    function_call_end_line
FROM
    syscall_condition_node_with_functions
WHERE
    function_file_path = $file_path AND (
        function_end_line = $end_line
    );