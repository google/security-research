/**
 * @name Kernel configs needed
 * @description Extracts preprocessor branch guards (#ifdef, #ifndef, #if defined,
 *   #if IS_ENABLED/IS_BUILTIN/IS_MODULE, #elif) referencing CONFIG_* symbols,
 *   along with their file path, start line, end line, and else line (or 0 if none).
 *   Produces the `configs` table in the SQLite database.
 * @id cpp/dashboard/kernel-configs-needed
 * @kind table
 * @tags security kernel
 */

import cpp

/**
 * Normalizes a raw preprocessor condition head into a single-line string,
 * stripping line continuations and collapsing whitespace.
 */
bindingset[raw]
string sanitizeConfigHead(string raw) {
  result =
    raw.replaceAll("\\", " ")
        .replaceAll("\n", " ")
        .replaceAll("\r", " ")
        .replaceAll("\t", " ")
        .regexpReplaceAll("  +", " ")
        .trim()
}

/**
 * Returns the formatted config expression for a PreprocessorBranch, prefixing
 * `#ifndef` directives with `!` to preserve negation polarity.
 */
string getBranchConfig(PreprocessorBranch pb) {
  exists(string rawHead |
    rawHead = pb.getHead() and
    rawHead.matches("%CONFIG_%") and
    rawHead.regexpMatch(".*\\bCONFIG_[A-Za-z0-9_]+.*") and
    if pb instanceof PreprocessorIfndef
    then result = "!" + sanitizeConfigHead(rawHead)
    else result = sanitizeConfigHead(rawHead)
  )
}

/**
 * Computes the `#else` line of a PreprocessorBranch (or 0 if none).
 */
int getElseLine(PreprocessorBranch pb) {
  exists(PreprocessorElse pe |
    pe = pb.getNext() and
    result = pe.getLocation().getStartLine()
  )
  or
  not pb.getNext() instanceof PreprocessorElse and
  result = 0
}

/**
 * Computes the effective end line of a PreprocessorBranch:
 * - If followed by `#elif`, the current branch's active range ends at the `#elif` line.
 * - Otherwise, it ends at the matching `#endif` line.
 */
int getEndLine(PreprocessorBranch pb) {
  if pb.getNext() instanceof PreprocessorElif
  then result = pb.getNext().getLocation().getStartLine()
  else result = pb.getEndIf().getLocation().getStartLine()
}

from PreprocessorBranch pb, string config, int ifdef, int endif, int else_
where
  config = getBranchConfig(pb) and
  ifdef = pb.getLocation().getStartLine() and
  endif = getEndLine(pb) and
  else_ = getElseLine(pb) and
  ifdef < endif and
  (else_ = 0 or (ifdef < else_ and else_ < endif))
select config,
  pb.getFile().getRelativePath() as path,
  ifdef,
  endif,
  else_


