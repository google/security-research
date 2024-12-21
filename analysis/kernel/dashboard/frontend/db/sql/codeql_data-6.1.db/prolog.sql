CREATE TABLE IF NOT EXISTS edges_with_functions AS
SELECT rule_id,
    group_concat(distinct target_function.function_name) target_function_names,
    min(target_function.start_line) target_function_start_line,
    max(target_function.end_line) target_function_end_line,
    group_concat(distinct source_function.function_name) source_function_names,
    min(source_function.start_line) source_function_start_line,
    max(source_function.end_line) source_function_end_line,
    targets.message target_message,
    targets.uri target_uri,
    targets.startLine target_startLine,
    targets.startColumn target_startColumn,
    targets.endLine target_endLine,
    targets.endColumn target_endColumn,
    sources.message source_message,
    sources.uri source_uri,
    sources.startLine source_startLine,
    sources.startColumn source_startColumn,
    sources.endLine source_endLine,
    sources.endColumn source_endColumn
FROM edges
    JOIN locations targets ON (targets.id = edges.target_location_id)
    JOIN locations sources ON (sources.id = edges.source_location_id)
    LEFT JOIN function_locations target_function ON (
        target_function.file_path = targets.uri
        AND target_function.function_name = targets.message
    )
    LEFT JOIN function_locations source_function ON (
        source_function.file_path = sources.uri
        AND source_function.start_line <= sources.startLine
        AND source_function.end_line >= sources.startLine
    )
GROUP BY rule_id,
    target_message,
    target_uri,
    target_startLine,
    target_startColumn,
    target_endLine,
    target_endColumn,
    source_message,
    source_uri,
    source_startLine,
    source_startColumn,
    source_endLine,
    source_endColumn;

CREATE TABLE IF NOT EXISTS syscall_node_with_functions AS
SELECT DISTINCT
    syscall,
    syscall_location,
    function,
    substr(function_location, 0, instr(function_location, ':')) function_file_path,
    start_line function_start_line,
    end_line function_end_line
FROM syscall_node
JOIN function_locations ON (
    file_path = function_file_path
    AND function_name = function
);

CREATE TABLE IF NOT EXISTS syscall_all AS
SELECT DISTINCT
    SUBSTR(syscall, length('__do_sys_') + 1) syscall
FROM syscall_node;

CREATE TABLE IF NOT EXISTS edges_with_functions_per_syscall AS
SELECT DISTINCT
    s1.syscall syscall,
    s1.syscall_location syscall_location,
    rule_id,
    target_function_names,
    target_function_start_line,
    target_function_end_line,
    source_function_names,
    source_function_start_line,
    source_function_end_line,
    target_message,
    target_uri,
    target_startLine,
    target_startColumn,
    target_endLine,
    target_endColumn,
    source_message,
    source_uri,
    source_startLine,
    source_startColumn,
    source_endLine,
    source_endColumn
FROM
    edges_with_functions
JOIN
    syscall_node_with_functions s1 ON (
        rule_id = 'callgraph-all'
        AND source_uri = s1.function_file_path
        AND source_function_start_line = s1.function_start_line
    )
JOIN
    syscall_node_with_functions s2 ON (
        s1.syscall = s2.syscall
        AND target_uri = s2.function_file_path
        AND target_function_start_line = s2.function_start_line
    );

CREATE TABLE IF NOT EXISTS conditions_split AS
SELECT DISTINCT
    type,
    argument,
    SUBSTR(call_location, 0, INSTR(call_location, ':')) call_file_path,
    1 * SUBSTR(call_location, INSTR(call_location, ':') + 1) call_line,
    call_location
FROM conditions;

CREATE TABLE IF NOT EXISTS syscall_condition_node AS
SELECT DISTINCT
    syscall_node_with_functions.syscall,
    conditions_split.type,
    conditions_split.argument,
    conditions_split.call_file_path,
    conditions_split.call_line,
    function_locations.file_path function_file_path,
    function_locations.start_line function_start_line,
    function_locations.end_line function_end_line
FROM
    conditions_split
INNER JOIN
    syscall_node_with_functions ON (
        conditions_split.call_file_path = syscall_node_with_functions.function_file_path AND
        conditions_split.call_line BETWEEN syscall_node_with_functions.function_start_line AND syscall_node_with_functions.function_end_line
    )
LEFT JOIN
    conditions_node ON (
        conditions_node.conditions_location = conditions_split.call_location
    )
LEFT JOIN
    function_locations ON (
        function_locations.file_path = substr(conditions_node.function_location, 0, instr(conditions_node.function_location, ':')) AND
        function_locations.function_name = conditions_node.function
    );

CREATE TABLE IF NOT EXISTS syscall_condition_node_with_functions AS
SELECT DISTINCT
    SUBSTR(syscall, LENGTH('__do_sys_') + 1) syscall,
    type,
    argument,
    function_locations.file_path function_call_file_path,
    function_locations.start_line function_call_start_line,
    function_locations.end_line function_call_end_line,
    function_file_path,
    function_start_line,
    function_end_line
FROM
    syscall_condition_node
LEFT JOIN function_locations ON (
    function_locations.file_path = syscall_condition_node.call_file_path AND
    syscall_condition_node.call_line BETWEEN function_locations.start_line AND function_locations.end_line
);

CREATE TABLE IF NOT EXISTS macro_edges AS
SELECT DISTINCT
    macro_name,
    macroinvocation_locations.file_path edge_file_path,
    macroinvocation_locations.start_line edge_start_line,
    macro_locations.file_path macro_file_path,
    macro_locations.start_line macro_start_line,
    macro_locations.end_line macro_end_line
FROM macroinvocation_locations
JOIN macro_locations ON (macroinvocation_name=macro_name);

CREATE INDEX IF NOT EXISTS getConditionsByFileLine1 ON syscall_condition_node_with_functions (
    function_file_path,
    function_start_line,
    syscall,
    type,
    argument,
    function_call_file_path,
    function_call_start_line,
    function_call_end_line
);

CREATE INDEX IF NOT EXISTS getConditionsByFileLine2 ON syscall_condition_node_with_functions (
    function_file_path,
    function_end_line,
    syscall,
    type,
    argument,
    function_call_file_path,
    function_call_start_line,
    function_call_end_line
);

CREATE INDEX IF NOT EXISTS getSyscallParentEdgesByFileLine ON edges_with_functions_per_syscall (
    syscall,
    target_uri,
    target_function_end_line,
    source_uri,
    source_function_end_line
);

CREATE INDEX IF NOT EXISTS getChildEdgesByFileLine ON edges_with_functions (
    rule_id,
    source_uri,
    source_startLine,
    source_message,
    target_startLine,
    target_uri,
    target_function_end_line
);

CREATE INDEX IF NOT EXISTS getParentEdgesByFileLine1 ON edges_with_functions_per_syscall (
    rule_id,
    target_uri,
    target_startLine,
    target_function_end_line,
    source_uri,
    source_function_start_line,
    source_function_end_line,
    source_function_names,
    syscall
);

CREATE INDEX IF NOT EXISTS getParentEdgesByFileLine2 ON edges_with_functions_per_syscall (
    rule_id,
    target_uri,
    target_function_end_line,
    target_startLine,
    source_uri,
    source_function_start_line,
    source_function_end_line,
    source_function_names,
    syscall
);

CREATE INDEX IF NOT EXISTS getSyscallsByFileLine ON syscall_node_with_functions (
    function_file_path,
    function_start_line,
    function_end_line,
    syscall
);

CREATE INDEX IF NOT EXISTS getSyscallParentEdgesByFileLine ON edges_with_functions_per_syscall (
    syscall,
    target_uri,
    target_function_end_line,
    source_uri,
    source_function_end_line
);

CREATE INDEX IF NOT EXISTS getAllEdgesFromFileLine_ops ON ops_targets (
    exprcall_file,
    exprcall_line,
    field,
    target_file,
    target_start,
    target_end
);

CREATE INDEX IF NOT EXISTS getAllEdgesFromFileLine_edges ON edges_with_functions (
    rule_id,
    source_uri,
    source_startLine,
    source_message,
    target_uri,
    target_startLine,
    target_function_end_line
);

CREATE INDEX IF NOT EXISTS getAllEdgesFromFileLine_macros ON macro_edges (
    edge_file_path,
    edge_start_line,
    macro_name,
    macro_file_path,
    macro_start_line,
    macro_end_line
);