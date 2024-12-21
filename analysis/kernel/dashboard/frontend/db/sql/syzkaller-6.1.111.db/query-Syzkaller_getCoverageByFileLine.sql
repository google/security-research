SELECT
    file_path,
    code_line_no,
    prog_id
FROM syzk_cov_with_file_path
WHERE
    file_path = $file_path
    AND code_line_no >= $start_line
    AND code_line_no <= $end_line;