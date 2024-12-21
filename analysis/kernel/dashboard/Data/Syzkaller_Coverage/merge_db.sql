CREATE TABLE IF NOT EXISTS syzk_prog (
    prog_id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL, -- Make prog_id autoincrement
    prog_code TEXT NOT NULL,
    UNIQUE (prog_code)
);

CREATE TABLE IF NOT EXISTS syzk_cov (
    file_id UNSIGNED BIG INT NOT NULL,
    code_line_no UNSIGNED BIG INT NOT NULL,
    prog_id UNSIGNED BIG INT NOT NULL,
    PRIMARY KEY (file_id, code_line_no, prog_id),
    UNIQUE (file_id, code_line_no, prog_id) -- Add unique constraint for all columns
);

CREATE TABLE IF NOT EXISTS file_path (
    file_id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL, -- Make prog_id autoincrement
    file_path TEXT NOT NULL,
    UNIQUE (file_path)
);

SELECT "attaching database";
ATTACH DATABASE 'new.db' AS db1;

SELECT "creating prog_id index";
CREATE INDEX IF NOT EXISTS db1.syzk_prog_id ON syzk_prog (prog_id);

SELECT "creating prog_code index";
CREATE INDEX IF NOT EXISTS db1.syzk_prog_code ON syzk_prog (prog_code);

SELECT "creating file_id index";
CREATE INDEX IF NOT EXISTS db1.file_path_id ON file_path (file_id);

SELECT "creating file_path index";
CREATE INDEX IF NOT EXISTS db1.file_path_path ON file_path (file_path);

SELECT "adding file paths";
INSERT OR IGNORE INTO file_path (file_path) SELECT file_path FROM db1.file_path;
SELECT '  added rows: ' || CAST(changes() AS TEXT);

SELECT "adding program codes";
INSERT OR IGNORE INTO syzk_prog (prog_code) SELECT prog_code FROM db1.syzk_prog;
SELECT '  added rows: ' || CAST(changes() AS TEXT);

SELECT "creating prog_id index";
CREATE INDEX IF NOT EXISTS syzk_prog_id ON syzk_prog (prog_id);

SELECT "creating prog_code index";
CREATE INDEX IF NOT EXISTS syzk_prog_code ON syzk_prog (prog_code);

SELECT "altering old table";
ALTER TABLE db1.syzk_prog ADD COLUMN new_prog_id INTEGER;

SELECT "altering old table";
ALTER TABLE db1.file_path ADD COLUMN new_file_id INTEGER;

SELECT "getting new prog ids";
UPDATE db1.syzk_prog SET new_prog_id = (SELECT prog_id FROM syzk_prog WHERE prog_code = db1.syzk_prog.prog_code);

SELECT "getting new file ids";
UPDATE db1.file_path SET new_file_id = (SELECT file_id FROM file_path WHERE file_path = db1.file_path.file_path);

SELECT "adding coverage";
INSERT OR IGNORE INTO syzk_cov (file_id, code_line_no, prog_id)
  SELECT
    (SELECT new_file_id FROM db1.file_path WHERE file_id = db1.file_path.file_id),
    code_line_no,
    (SELECT new_prog_id FROM db1.syzk_prog WHERE prog_id = db1.syzk_cov.prog_id)
  FROM db1.syzk_cov;
SELECT '  added rows: ' || CAST(changes() AS TEXT);

