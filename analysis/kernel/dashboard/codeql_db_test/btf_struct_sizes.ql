/**
 * @name CodeQL Kernel Struct Size Extraction for BTF Ground-Truth Cross-Validation
 * @description Extracts (struct_name, byte_size) from CodeQL's type table to compare
 *              against DWARF/BTF ground truth. Uses max(s.getSize()) per struct name
 *              to select the 64-bit LP64 kernel struct definition rather than 32-bit
 *              VDSO/boot-stub definitions.
 * @kind table
 * @id cpp/kernel-db-test/btf-struct-sizes
 */

import cpp

from string struct_name, int codeql_size
where
  exists(Struct s |
    s.hasDefinition() and
    s.getName() = struct_name and
    not struct_name.matches("(%") and
    not struct_name.matches("__anonymous%") and
    s.getSize() > 0
  ) and
  codeql_size = max(Struct s |
    s.hasDefinition() and
    s.getName() = struct_name and
    s.getSize() > 0 |
    s.getSize()
  )
select
  struct_name,
  codeql_size
