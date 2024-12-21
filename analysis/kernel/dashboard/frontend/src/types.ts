export type CHILD_EDGE_LOCATIONS = {
    source_message: string;
    target_startLine: string;
    target_uri: string;
    target_function_end_line: string;
};

export type PARENT_EDGE_LOCATIONS = {
    source_uri: string;
    source_function_start_line: string;
    source_function_end_line: string;
    source_function_names: string;
    syscalls: string;
};

export type COVERAGE_PROGRAMS = {
    file_path: string;
    code_line_no: string;
    prog_id: string;
};

export type SYSCALL_NAMES = {
    syscall: string;
};

export type SYZKALL_NAMES = {
    syscall: string;
    prog_id: string;
};

export type STRUCT_RESULTS = {
    struct_name: string;
    struct_size: string;
    allocSizeMax: string;
    allocSizeMin: string;
    allocSize: string;
    call_startLine: string;
    call_uri: string;
    call_value: string;
    depth: string;
    flagsMax: string;
    flagsMin: string;
    flags: string;
    function: string;
    function_start_line: string;
    function_end_line: string;
    syscalls_num: string;
    kmalloc_bucket_name: string;
    kmalloc_cgroup_name: string;
    kmalloc_dyn: string;
};

export type FIELDS_RESULTS = {
    bits_offset: string;
    bits_end: string;
    type: string;
    parent_type: string;
    name: string;
};

export type ACCESS_RESULTS = {
    struct_name: string;
    type: string;
    full_field_name: string;
    bits_offset: string;
    bits_end: string;
    field_access_type: string;
    field_access_start_line: string;
    function_file_path: string;
    function_start_line: string;
    function_end_line: string;
    syscalls_num: string;
};

export type CONDITION_LOCATIONS = {
    syscall: string;
    condition_type: string;
    condition_argument: string;
    function_call_file_path: string;
    function_call_start_line: string;
    function_call_end_line: string;
};

export type ALL_EDGES_LOCATIONS = {
    edge_type: string;
    identifier: string;
    file_path: string;
    start_line: string;
    end_line: string;
};