ATTACH DATABASE 'allocs.db' AS allocs;
ATTACH DATABASE 'codeql_data-6.1.db' AS codeql;

CREATE TABLE IF NOT EXISTS kmalloc_bucket AS
SELECT
    column1 AS min,
    column2 AS max,
    column3 AS name
FROM (
    VALUES
        (1,     8,      '8'),
        (9,     16,     '16'),
        (17,    32,     '32'),
        (33,    64,     '64'),
        (65,    96,     '96'),
        (97,    128,    '128'),
        (129,   192,    '192'),
        (193,   256,    '256'),
        (257,   512,    '512'),
        (513,   1024,   '1k'),
        (1025,  2048,   '2k'),
        (2049,  4096,   '4k'),
        (4097,  8192,   '8k')
);

CREATE TABLE IF NOT EXISTS kmalloc_cgroup AS
SELECT
    column1 AS mask,
    column2 AS name
FROM (
    VALUES
        (/*GFP_KERNEL_ACCOUNT =*/ (
            /*GFP_KERNEL*/ (
                /*GFP_RECLAIM*/ (
                    /*GFP_DIRECT_RECLAIM*/ 0x400 |
                    /*GFP_KSWAPD_RECLAIM*/ 0x800
                ) |
                /*GFP_IO*/ 0x40 |
                /*GFP_FS*/ 0x80
            ) |
            /*GFP_ACCOUNT*/ (
                0x100000
            )
        ), 'cg')
);

CREATE TABLE IF NOT EXISTS function_locations_clean AS
SELECT DISTINCT
    file_path,
    start_line,
    end_line,
    function_name
FROM
    function_locations;

CREATE INDEX IF NOT EXISTS function_locations_clean_tmp ON function_locations_clean (
    file_path,
    start_line,
    end_line,
    function_name
);

CREATE TABLE IF NOT EXISTS syscall_node_clean AS
SELECT DISTINCT
    substr(function_location, 0, instr(function_location, ':')) function_file_path,
    function,
    syscall
FROM
    syscall_node;

CREATE INDEX IF NOT EXISTS syscall_node_clean_tmp ON syscall_node_clean (
    function_file_path,
    function,
    syscall
);

CREATE TABLE IF NOT EXISTS function_to_syscall AS
SELECT
    function_locations_clean.file_path,
    function_locations_clean.start_line,
    function_locations_clean.end_line,
    COUNT(DISTINCT syscall) syscalls_num
FROM
    syscall_node_clean INDEXED BY syscall_node_clean_tmp
LEFT JOIN
    function_locations_clean INDEXED BY function_locations_clean_tmp
    ON (
        syscall_node_clean.function_file_path = function_locations_clean.file_path AND
        syscall_node_clean.function = function_locations_clean.function_name
    )
GROUP BY
    file_path,
    start_line,
    end_line;

CREATE INDEX IF NOT EXISTS function_to_syscall_tmp ON function_to_syscall (
    file_path,
    start_line,
    end_line,
    syscalls_num
);

CREATE TABLE IF NOT EXISTS fields_with_allocs AS
SELECT DISTINCT
    struct_name,
    struct_size,
    parent_type,
    kind,
    type,
    RTRIM(SUBSTR(
        types.name,
        LENGTH(RTRIM(
            types.name, REPLACE(REPLACE(
                types.name, '/', ''
            ), '.', '')
        )) + 1),
        '[0123456789]'
    ) field_name,
    types.name full_field_name,
    bits_offset,
    nr_bits,
    bits_end,
    is_flex,
    CAST(allocSizeMax_value AS decimal) allocSizeMax,
    CAST(allocSizeMin_value AS decimal) allocSizeMin,
    CAST(allocSize_value AS decimal) allocSize,
    call_startColumn,
    call_startLine,
    call_uri,
    call_value,
    CAST(depth_value AS decimal) depth,
    CAST(flagsMax_value AS decimal) flagsMax,
    CAST(flagsMin_value AS decimal) flagsMin,
    CAST(flags_value AS decimal) flags,
    type_startColumn,
    type_startLine,
    type_uri,
    type_value,
    function_locations.function_name function,
    function_locations.start_line function_start_line,
    function_locations.end_line function_end_line,
    syscall_node_clean.syscall syscall,
    kmalloc_cgroup.name kmalloc_cgroup_name,
    kmalloc_bucket.name kmalloc_bucket_name,
    kmalloc_bucket.min kmalloc_bucket_min,
    kmalloc_bucket.max kmalloc_bucket_max,
    (allocSizeMax_value <> allocSizeMin_value) kmalloc_dyn
FROM
    types
LEFT JOIN allocs ON (
    type_value = struct_name AND
    CAST(objectSize_value AS decimal) = struct_size
)
LEFT JOIN function_locations_clean AS function_locations INDEXED BY function_locations_clean_tmp ON (
    function_locations.file_path = allocs.call_uri
    AND function_locations.start_line <= allocs.call_startLine
    AND function_locations.end_line >= allocs.call_startLine
)
LEFT JOIN syscall_node_clean INDEXED BY syscall_node_clean_tmp ON (
    function_locations.file_path = syscall_node_clean.function_file_path
    AND function_locations.function_name = syscall_node_clean.function
)
LEFT JOIN kmalloc_bucket ON (
    allocSizeMax >= kmalloc_bucket.min AND
    allocSizeMin <= kmalloc_bucket.max
)
LEFT JOIN kmalloc_cgroup ON (
    kmalloc_cgroup.mask BETWEEN flagsMin AND flagsMax
)
WHERE
    struct_name <> '(anon)';

CREATE TABLE IF NOT EXISTS field_access_clean AS
SELECT DISTINCT
    field_access.type field_access_type,
    SUBSTR(field_access.location, 0, instr(field_access.location, ':')) field_access_uri,
    1 * SUBSTR(field_access.location, instr(field_access.location, ':') + 1) field_access_start_line,
    field_access.field field_access_field,
    field_access.parent field_access_parent
FROM
    field_access
WHERE
    parent NOT LIKE '(%';

CREATE INDEX IF NOT EXISTS field_access_clean_tmp ON field_access_clean (
    field_access_field,
    field_access_parent,
    field_access_uri,
    field_access_start_line,
    field_access_type
);

CREATE INDEX IF NOT EXISTS fields_with_allocs_tmp ON fields_with_allocs (
    field_name,
    parent_type,

    struct_name,
    struct_size,
    kind,
    type,
    full_field_name,
    bits_offset,
    nr_bits,
    bits_end,
    is_flex,
    allocSizeMax,
    allocSizeMin,
    allocSize,
    call_startColumn,
    call_startLine,
    call_uri,
    call_value,
    depth,
    flagsMax,
    flagsMin,
    flags,
    type_startColumn,
    type_startLine,
    type_uri,
    type_value,
    kmalloc_cgroup_name,
    kmalloc_bucket_name,
    kmalloc_bucket_min,
    kmalloc_bucket_max,
    kmalloc_dyn
);

CREATE TABLE IF NOT EXISTS fields_with_allocs_and_access AS
SELECT DISTINCT
    field_access_clean.field_access_type field_access_type,
    field_access_clean.field_access_uri field_access_uri,
    field_access_clean.field_access_start_line field_access_start_line,
    fields_with_allocs.struct_name struct_name,
    fields_with_allocs.struct_size struct_size,
    fields_with_allocs.parent_type parent_type,
    fields_with_allocs.kind kind,
    fields_with_allocs.type type,
    fields_with_allocs.field_name field_name,
    fields_with_allocs.full_field_name full_field_name,
    fields_with_allocs.bits_offset bits_offset,
    fields_with_allocs.nr_bits nr_bits,
    fields_with_allocs.bits_end bits_end,
    fields_with_allocs.is_flex is_flex,
    fields_with_allocs.allocSizeMax allocSizeMax,
    fields_with_allocs.allocSizeMin allocSizeMin,
    fields_with_allocs.allocSize allocSize,
    fields_with_allocs.call_startColumn call_startColumn,
    fields_with_allocs.call_startLine call_startLine,
    fields_with_allocs.call_uri call_uri,
    fields_with_allocs.call_value call_value,
    fields_with_allocs.depth depth,
    fields_with_allocs.flagsMax flagsMax,
    fields_with_allocs.flagsMin flagsMin,
    fields_with_allocs.flags flags,
    fields_with_allocs.type_startColumn type_startColumn,
    fields_with_allocs.type_startLine type_startLine,
    fields_with_allocs.type_uri type_uri,
    fields_with_allocs.type_value type_value,
    fields_with_allocs.kmalloc_cgroup_name kmalloc_cgroup_name,
    fields_with_allocs.kmalloc_bucket_name kmalloc_bucket_name,
    fields_with_allocs.kmalloc_bucket_min kmalloc_bucket_min,
    fields_with_allocs.kmalloc_bucket_max kmalloc_bucket_max,
    fields_with_allocs.kmalloc_dyn kmalloc_dyn
FROM
    field_access_clean INDEXED BY field_access_clean_tmp
INNER JOIN
    fields_with_allocs INDEXED BY fields_with_allocs_tmp ON (
        fields_with_allocs.field_name=field_access_clean.field_access_field AND
        fields_with_allocs.parent_type=field_access_clean.field_access_parent
    )
WHERE
    kmalloc_bucket_name IS NOT NULL;

CREATE INDEX IF NOT EXISTS fields_with_allocs_and_access_tmp ON fields_with_allocs_and_access (
    field_access_uri,
    field_access_start_line,

    field_access_type,
    struct_name,
    type,
    full_field_name,
    bits_offset,
    bits_end,
    kmalloc_cgroup_name,
    kmalloc_bucket_name,
    kmalloc_dyn
);

CREATE TABLE IF NOT EXISTS fields_with_allocs_and_access_and_functions AS
SELECT
    field_access_type,
    field_access_uri,
    field_access_start_line,
    struct_name,
    type,
    full_field_name,
    bits_offset,
    bits_end,
    kmalloc_cgroup_name,
    kmalloc_bucket_name,
    kmalloc_dyn,
    function_to_syscall.file_path function_file_path,
    function_to_syscall.start_line function_start_line,
    function_to_syscall.end_line function_end_line,
    function_to_syscall.syscalls_num
FROM
    fields_with_allocs_and_access INDEXED BY fields_with_allocs_and_access_tmp
INNER JOIN function_to_syscall INDEXED BY function_to_syscall_tmp ON (
    field_access_uri = function_to_syscall.file_path AND
    field_access_start_line BETWEEN function_to_syscall.start_line AND function_to_syscall.end_line
)
GROUP BY
    field_access_type,
    field_access_uri,
    field_access_start_line,
    struct_name,
    type,
    full_field_name,
    bits_offset,
    bits_end,
    kmalloc_cgroup_name,
    kmalloc_bucket_name,
    kmalloc_dyn,
    function_file_path,
    function_start_line,
    function_end_line;

CREATE INDEX IF NOT EXISTS getAccessByCache ON fields_with_allocs_and_access_and_functions (
    kmalloc_bucket_name,
    kmalloc_cgroup_name,
    bits_end,
    bits_offset,
    struct_name,
    type,
    full_field_name,
    field_access_type,
    field_access_start_line,
    function_file_path,
    function_start_line,
    function_end_line,
    syscalls_num
);

CREATE INDEX IF NOT EXISTS types_tmp ON types (
    RTRIM(SUBSTR(
        name,
        LENGTH(RTRIM(
            name, REPLACE(REPLACE(
                name, '/', ''
            ), '.', '')
        )) + 1),
        '[0123456789]'
    ),
    parent_type,
    type,
    bits_offset,
    bits_end,
    name
);

CREATE TABLE IF NOT EXISTS fields_with_access AS
SELECT DISTINCT
    field_access_clean.field_access_type field_access_type,
    field_access_clean.field_access_uri field_access_uri,
    field_access_clean.field_access_start_line field_access_start_line,
    types.struct_name struct_name,
    types.type type,
    types.name full_field_name,
    types.bits_offset bits_offset,
    types.bits_end bits_end,
    function_to_syscall.file_path function_file_path,
    function_to_syscall.start_line function_start_line,
    function_to_syscall.end_line function_end_line,
    function_to_syscall.syscalls_num syscalls_num
FROM
    types INDEXED BY types_tmp
INNER JOIN
    field_access_clean INDEXED BY field_access_clean_tmp ON (
        field_access_field = RTRIM(SUBSTR(
            types.name,
            LENGTH(RTRIM(
                types.name, REPLACE(REPLACE(
                    types.name, '/', ''
                ), '.', '')
            )) + 1),
            '[0123456789]'
        ) AND
        field_access_parent = types.parent_type
    )
INNER JOIN function_to_syscall INDEXED BY function_to_syscall_tmp ON (
    field_access_uri = function_to_syscall.file_path AND
    field_access_start_line BETWEEN function_to_syscall.start_line AND function_to_syscall.end_line
);

CREATE INDEX IF NOT EXISTS getAccessByStruct ON fields_with_access (
    struct_name,
    bits_end,
    bits_offset,

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
);

CREATE TABLE IF NOT EXISTS structs_with_allocs AS
SELECT DISTINCT
    struct_name,
    parent_type,
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
    syscall,
    kmalloc_cgroup_name,
    kmalloc_bucket_name,
    kmalloc_bucket_min,
    kmalloc_bucket_max,
    kmalloc_dyn
FROM
    fields_with_allocs;

CREATE TABLE IF NOT EXISTS structs_with_allocs_search AS
SELECT
    struct_name struct_or_parent,
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
    syscall,
    kmalloc_cgroup_name,
    kmalloc_bucket_name,
    kmalloc_bucket_min,
    kmalloc_bucket_max,
    kmalloc_dyn
FROM structs_with_allocs
UNION
SELECT
    parent_type struct_or_parent,
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
    syscall,
    kmalloc_cgroup_name,
    kmalloc_bucket_name,
    kmalloc_bucket_min,
    kmalloc_bucket_max,
    kmalloc_dyn
FROM structs_with_allocs;

CREATE TABLE IF NOT EXISTS structs_with_allocs_syscall_num AS
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
    COUNT(DISTINCT syscall) FILTER (WHERE syscall IS NOT NULL) syscalls_num,
    kmalloc_bucket_name,
    kmalloc_cgroup_name,
    kmalloc_dyn
FROM
    structs_with_allocs
GROUP BY
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
    kmalloc_bucket_name,
    kmalloc_cgroup_name,
    kmalloc_dyn;

CREATE INDEX IF NOT EXISTS getStructsByStructName ON structs_with_allocs_search (
    struct_or_parent,
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
    syscall,
    kmalloc_cgroup_name,
    kmalloc_bucket_name,
    kmalloc_dyn
);

CREATE INDEX IF NOT EXISTS getStructsByAllocation ON structs_with_allocs_syscall_num (
    kmalloc_bucket_name,
    kmalloc_cgroup_name,
    kmalloc_dyn,
    allocSizeMin,
    allocSizeMax,
    flagsMin,
    flagsMax,
    allocSize,
    flags,
    struct_name,
    struct_size,
    call_startLine,
    call_uri,
    call_value,
    depth,
    function,
    function_start_line,
    function_end_line,
    syscalls_num
);

CREATE INDEX IF NOT EXISTS getFieldsByStructName ON types (
    struct_name,
    bits_offset,
    name,
    parent_type,
    bits_end,
    type
);
