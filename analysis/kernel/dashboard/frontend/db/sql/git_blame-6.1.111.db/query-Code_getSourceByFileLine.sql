SELECT file_path, line_no, data
FROM git_blame
WHERE
    file_path = $file_path
    AND line_no >= $start_line
    AND line_no <= $end_line;