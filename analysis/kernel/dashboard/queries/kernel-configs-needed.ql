/**
 * @name Kernel configs needed
 * @description Extracts preprocessor branch guards (CONFIG_*) with their file path,
 *   start line (#ifdef/#if), #endif line, and #else line (or 0 if none).
 *   Produces the `configs` table in the SQLite database.
 * @id cpp/dashboard/kernel-configs-needed
 * @kind table
 * @tags security kernel
 */

import cpp

int getElseLine(PreprocessorBranch pb) {
  exists(PreprocessorElse pe |
    pe = pb.getNext() and
    result = pe.getLocation().getStartLine()
  )
  or
  not pb.getNext() instanceof PreprocessorElse and
  result = 0
}

from PreprocessorBranch pb
where pb.getHead().matches("CONFIG%")
select pb.getHead() as config,
  pb.getFile().getRelativePath() as path,
  pb.getLocation().getStartLine() as ifdef,
  pb.getEndIf().getLocation().getStartLine() as endif,
  getElseLine(pb) as else_
