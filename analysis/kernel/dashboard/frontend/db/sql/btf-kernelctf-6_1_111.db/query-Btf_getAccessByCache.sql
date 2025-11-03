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
    fields_with_allocs_and_access_and_functions
WHERE
    kmalloc_bucket_name = $kmalloc_bucket_name AND
    kmalloc_cgroup_name is $kmalloc_cgroup_name AND
    bits_end >= $overlap_start AND
    bits_offset <= $overlap_end
LIMIT $limit
OFFSET $offset;
