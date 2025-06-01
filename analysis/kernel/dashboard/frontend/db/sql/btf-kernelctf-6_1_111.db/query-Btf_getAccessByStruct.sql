SELECT
    struct_name,
    type,
    full_field_name,
    bits_offset,
    bits_end,
    field_access_type,
    field_access_start_line,
    function_file_path,
    function_start_line,
    function_end_line,
    syscalls_num
FROM
    fields_with_access
WHERE
    struct_name = $struct_name AND
    bits_end >= $overlap_start AND
    bits_offset <= $overlap_end
LIMIT $limit
OFFSET $offset;
