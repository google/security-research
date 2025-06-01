SELECT
    prog_code
FROM syzk_prog
WHERE
    prog_id IN (SELECT value FROM json_each($prog_ids));