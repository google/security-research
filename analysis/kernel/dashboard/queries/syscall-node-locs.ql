/**
 * @name Function location components
 * @description Emits each function's name and definition location as separate
 *   columns (file, startLine, startCol, endLine, endCol) rather than an assembled
 *   string.
 * @id cpp/dashboard/syscall-node-locs
 * @kind table
 */

import cpp
import kernel_common

from Function f, BlockStmt block, File fFile, int sLine, int eLine
where
  not f.getName().matches("__compiletime_assert_%") and
  not f.getName().matches("__builtin_%") and
  f.getBlock() = block and
  fFile = block.getLocation().getFile() and
  not nonRuntimeKernelFile(fFile) and
  sLine = blockStartLine(f, block) and
  eLine = block.getLocation().getEndLine()
select
  f.getName() as name,
  fFile.getRelativePath() as file,
  sLine as startLine,
  f.getLocation().getStartColumn() as startCol,
  eLine as endLine,
  block.getLocation().getEndColumn() as endCol

