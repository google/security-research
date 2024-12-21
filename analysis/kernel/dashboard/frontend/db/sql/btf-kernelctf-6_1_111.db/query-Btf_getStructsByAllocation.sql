SELECT
    struct_name,
    struct_size,
    allocSizeMax,
    allocSizeMin,
    allocSize,
    call_startLine,
    call_uri,
    call_value,
    depth,
    flagsMax,
    flagsMin,
    flags,
    function,
    function_start_line,
    function_end_line,
    syscalls_num,
    kmalloc_bucket_name,
    kmalloc_cgroup_name,
    kmalloc_dyn
FROM
    structs_with_allocs_syscall_num
WHERE
    kmalloc_bucket_name = $kmalloc_bucket_name AND
    kmalloc_cgroup_name IS $kmalloc_cgroup_name
LIMIT $limit
OFFSET $offset;