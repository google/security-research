import cpp

boolean isInteresting(Field f) {
  // This sometimes allows for arbitrary write/read primitives
  // and migth allow you to leak a physmap addr
  f.getType().hasName("list_head") and
  result = true
  or
  // This is useful for kASLR bypass / RIP control
  f.getType().getName().regexpMatch(".*_ops|.*_operations") and
  result = true
  or
  // This is useful for RIP control
  f.getType() instanceof FunctionPointerType and
  result = true
  or
  result = false
}

// Returns all the parent struct of all fields, their name, their type, their offset and if they could be interesting
from Field f, Struct s
where
  s.getAField() = f and
  not s.isAnonymous()
select s.getName(), f.getName(), f.getType().toString(), f.getByteOffset(), isInteresting(f)
