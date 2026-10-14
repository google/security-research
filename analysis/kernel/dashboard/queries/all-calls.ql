/**
 * @name all-calls
 * @description Emits explicit source and target label, relative file path, and
 *   location span columns for every edge in the direct + points-to/taint call
 *   graph (call_graph_edges.qll).
 * @id callgraph-all
 * @kind table
 */

import cpp
import call_graph_edges

string nodeLabel(ControlFlowNode n) {
  result = n.(Function).getName()
  or
  result = "call to " + n.(FunctionCall).getTarget().getName()
  or
  n instanceof ExprCall and result = "call to function"
  or
  not n instanceof Function and
  not n instanceof FunctionCall and
  not n instanceof ExprCall and
  result = n.toString()
}

from
  ControlFlowNode nodeFrom,
  ControlFlowNode nodeTo,
  Location locFrom,
  Location locTo
where
  edges(nodeFrom, nodeTo) and
  locFrom = nodeFrom.getLocation() and
  locTo = nodeTo.getLocation()
select
  nodeLabel(nodeFrom) as src_label,
  locFrom.getFile().getRelativePath() as src_file,
  locFrom.getStartLine() as src_start_line,
  locFrom.getStartColumn() as src_start_col,
  locFrom.getEndLine() as src_end_line,
  locFrom.getEndColumn() as src_end_col,
  nodeLabel(nodeTo) as dst_label,
  locTo.getFile().getRelativePath() as dst_file,
  locTo.getStartLine() as dst_start_line,
  locTo.getStartColumn() as dst_start_col,
  locTo.getEndLine() as dst_end_line,
  locTo.getEndColumn() as dst_end_col


