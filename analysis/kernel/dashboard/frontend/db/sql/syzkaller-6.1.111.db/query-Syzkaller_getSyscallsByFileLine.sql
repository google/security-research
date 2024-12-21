SELECT DISTINCT
    syscall,
    prog_id
FROM
    syzk_cov_with_file_paths_and_syscalls
WHERE
    file_path = $file_path
    AND code_line_no >= $start_line
    AND code_line_no <= $end_line;