SELECT
    bits_offset,
    bits_end,
    type,
    parent_type,
    name
FROM types
WHERE
    struct_name = $struct_name
ORDER BY
    bits_offset ASC,
    name ASC;