/**
 * @name CodeQL Kernel Struct Size Extraction for BTF Ground-Truth Cross-Validation
 * @description Extracts (struct_name, byte_size) from CodeQL's type table to compare
 *              against DWARF/BTF `pahole --sizes` ground truth.
 * @kind table
 * @id linux-kernel/dashboard-struct-sizes-check
 */

import cpp

from Struct s
where
  s.hasDefinition() and
  not s.getName().matches("(%") and
  not s.getName().matches("__anonymous%") and
  s.getSize() > 0
select
  s.getName() as struct_name,
  min(s.getSize()) as codeql_size
