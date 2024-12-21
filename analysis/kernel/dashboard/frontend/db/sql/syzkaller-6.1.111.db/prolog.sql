CREATE TABLE IF NOT EXISTS syzk_cov_with_file_path AS
SELECT
    file_path,
    code_line_no,
    prog_id
FROM
    syzk_cov
JOIN
    file_path USING (file_id);

CREATE TABLE IF NOT EXISTS syzk_cov_with_file_paths_and_syscalls AS
SELECT
    prog_id,
    syscall,
    file_path,
    code_line_no
FROM syzk_sys JOIN syzk_cov_with_file_path USING (prog_id);

CREATE TABLE IF NOT EXISTS syzk_all_syscalls AS
SELECT DISTINCT
    syscall
FROM
    syzk_sys;

CREATE INDEX IF NOT EXISTS getCoverageByFileLine ON syzk_cov_with_file_path (
    file_path, code_line_no, prog_id
);

CREATE INDEX IF NOT EXISTS getSyscallsByFileLine ON syzk_cov_with_file_paths_and_syscalls (
    file_path, code_line_no, syscall
);
