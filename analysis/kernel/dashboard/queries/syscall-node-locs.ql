/**
 * @name Function location components
 * @description Emits each function's name and definition location as separate
 *   columns (file, startLine, startCol, endLine, endCol) rather than an assembled
 *   string.
 * @id cpp/dashboard/syscall-node-locs
 * @kind table
 */

import cpp

from Function f, Location l
where
  exists(f.getBlock()) and
  not f.getName().matches("__compiletime_assert_%") and
  not f.getName().matches("__builtin_%") and
  l = f.getLocation()
select
  f.getName() as name,
  l.getFile().getRelativePath() as file,
  l.getStartLine() as startLine,
  l.getStartColumn() as startCol,
  l.getEndLine() as endLine,
  l.getEndColumn() as endCol
