/**
 * Shared kernel scope filters and canonical function signature span predicates
 * used across dashboard CodeQL queries.
 */

import cpp

/**
 * Holds if `f` belongs to a standalone pre-boot binary, EFI firmware stub,
 * VDSO image, kexec purgatory, host build tool, or sample program rather than
 * the runtime kernel (`vmlinux` or loadable `.ko` modules).
 */
pragma[nomagic]
predicate nonRuntimeKernelFile(File f) {
  exists(string rel | rel = f.getRelativePath() |
    rel.matches("arch/%/boot/%") or
    rel.matches("drivers/firmware/efi/libstub/%") or
    rel.matches("%/vdso/%") or
    rel.matches("%/purgatory/%") or
    rel.matches("scripts/%") or
    rel.matches("tools/%") or
    rel.matches("samples/%") or
    rel.matches("usr/%") or
    rel.matches("Documentation/%")
  )
}

/**
 * Returns the canonical signature start line for a specific `block` of `f`
 * (starting at `fnLoc.getStartLine()` when `fnLoc` is in the same file as
 * `block` and precedes `block`, otherwise falling back to
 * `block.getLocation().getStartLine()`).
 *
 * Taking both `f` and `block` and binding `Location fnLoc` ensures that
 * functions with both a `__weak` stub (e.g. in `kernel/sys_ni.c` or
 * `init/main.c`) and a strong definition in another translation unit never
 * mix line numbers across files.
 */
pragma[nomagic]
int blockStartLine(Function f, BlockStmt block) {
  exists(File file, int blockStart, int fnStart |
    block = f.getBlock() and
    file = block.getLocation().getFile() and
    blockStart = block.getLocation().getStartLine() and
    fnStart = f.getLocation().getStartLine() and
    (
      if
        f.getLocation().getFile() = file and
        fnStart > 0 and
        fnStart <= blockStart and
        blockStart - fnStart <= 12
      then result = fnStart
      else result = blockStart
    )
  )
}

/**
 * Computes the canonical `(file, startLine, endLine)` span for a compiled
 * runtime kernel function `f`, starting at its declaration/signature line
 * (`f.getLocation().getStartLine()`) and ending at the closing brace of its
 * body (`f.getBlock().getLocation().getEndLine()`).
 */
pragma[nomagic]
predicate functionSignatureSpan(Function f, File file, int startLine, int endLine) {
  exists(BlockStmt block |
    f.getBlock() = block and
    file = block.getLocation().getFile() and
    not nonRuntimeKernelFile(file) and
    startLine = blockStartLine(f, block) and
    endLine = block.getLocation().getEndLine()
  )
}


