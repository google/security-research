/**
 * @name Syscall-reachable pairs
 * @description Emits (syscall, function, file) for every function reachable from each
 *   __do_sys_* entry over the full call graph (direct + indirect calls). Emitting
 *   the relative file path provides an exact join key (function, file) for location
 *   assembly while avoiding dynamic string concatenation in QL to prevent string-pool
 *   exhaustion.
 * @id cpp/dashboard/syscall-node-pairs
 * @kind table
 */

import cpp
import call_graph_edges

class SyscallEntry extends Function {
  SyscallEntry() { this.getName().regexpMatch("__do_sys_.*") and exists(this.getBlock()) }
}

from SyscallEntry entry, Function reached
where
  edges+(entry, reached) and
  reached != entry and
  not notInteresting(reached)
select
  entry.getName() as syscall,
  reached.getName() as function,
  reached.getFile().getRelativePath() as file
