CREATE INDEX IF NOT EXISTS getSourceByFileLine ON git_blame (file_path, line_no, data);
