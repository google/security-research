/**
 * Shared struct/union AST helpers for `structs.ql` and `field-acces-type.ql`.
 *
 * Handles anonymous C struct/union flattening, cumulative byte-offset
 * computation across anonymous containers, typedef struct naming, bitfield
 * metadata, and flexible array member detection.
 */

import cpp
import kernel_common

/**
 * Holds if `c` has an empty or compiler-synthesized `(unnamed...)` / `(unknown...)` name.
 */
predicate isAnonymousClass(Class c) {
  c.getName() = "" or c.getName().matches(["(unnamed%", "(unknown%"])
}

/**
 * Holds if `child` is an anonymous C `struct` or `union` nested directly
 * inside `parent` at byte offset `stepOffset` with optional field path prefix
 * `stepPrefix` (empty when the anonymous container field itself is unnamed).
 */
predicate anonClassParentStep(Class child, Class parent, int stepOffset, string stepPrefix) {
  isAnonymousClass(child) and
  (
    exists(Field af |
      af.getDeclaringType() = parent and
      af.getType().getUnderlyingType() = child and
      stepOffset = af.getByteOffset() and
      if af.getName() = "" or af.getName().matches(["(unnamed%", "(unknown%"])
      then stepPrefix = ""
      else stepPrefix = af.getName() + "."
    )
    or
    not exists(Field af |
      af.getDeclaringType() = parent and
      af.getType().getUnderlyingType() = child
    ) and
    parent = child.getEnclosingElement() and
    stepOffset = 0 and
    stepPrefix = ""
  )
}

/**
 * Holds if `child` is an anonymous C `struct` or `union` nested directly
 * inside `parent`.
 */
predicate anonClassParent(Class child, Class parent) {
  anonClassParentStep(child, parent, _, _)
}

/**
 * Resolves a top-level compiled kernel `Struct` or `Union` `s` to its
 * canonical `structName` and `isTypedef` flag (`0` for named `struct foo`,
 * `1` for `typedef struct { ... } foo_t`).
 */
predicate resolvedRootStruct(Class s, string structName, int isTypedef) {
  (s instanceof Struct or s instanceof Union) and
  s.hasDefinition() and
  exists(s.getAMember()) and
  not nonRuntimeKernelFile(s.getFile()) and
  (
    not isAnonymousClass(s) and
    structName = s.getName() and
    isTypedef = 0
    or
    isAnonymousClass(s) and
    not anonClassParent(s, _) and
    exists(TypedefType td |
      td.getBaseType() = s and
      td.getFile() = s.getFile() and
      not td.getName().matches(["", "(unnamed%", "(unknown%"]) and
      structName =
        min(TypedefType t |
          t.getBaseType() = s and
          t.getFile() = s.getFile() and
          not t.getName().matches(["", "(unnamed%", "(unknown%"])
        |
          t.getName()
        )
    ) and
    isTypedef = 1
  )
}

/**
 * Computes the cumulative byte offset `offset` and flattened path prefix
 * `prefix` from a root struct `root` to `declCls` (which is either `root`
 * itself or an anonymous `struct`/`union` nested up to 5 levels inside `root`).
 */
predicate anonChain(Class declCls, Class root, int offset, string prefix) {
  resolvedRootStruct(root, _, _) and
  (
    declCls = root and
    offset = 0 and
    prefix = ""
    or
    anonClassParentStep(declCls, root, offset, prefix)
    or
    exists(Class c1, int o1, int o2, string p1, string p2 |
      anonClassParentStep(declCls, c1, o2, p2) and
      anonClassParentStep(c1, root, o1, p1) and
      offset = o1 + o2 and
      prefix = p1 + p2
    )
    or
    exists(Class c1, Class c2, int o1, int o2, int o3, string p1, string p2, string p3 |
      anonClassParentStep(declCls, c2, o3, p3) and
      anonClassParentStep(c2, c1, o2, p2) and
      anonClassParentStep(c1, root, o1, p1) and
      offset = o1 + o2 + o3 and
      prefix = p1 + p2 + p3
    )
    or
    exists(
      Class c1, Class c2, Class c3, int o1, int o2, int o3, int o4, string p1, string p2,
      string p3, string p4
    |
      anonClassParentStep(declCls, c3, o4, p4) and
      anonClassParentStep(c3, c2, o3, p3) and
      anonClassParentStep(c2, c1, o2, p2) and
      anonClassParentStep(c1, root, o1, p1) and
      offset = o1 + o2 + o3 + o4 and
      prefix = p1 + p2 + p3 + p4
    )
  )
}

/**
 * Holds if `f` is a concrete leaf member field belonging to `root` (either
 * declared directly on `root` or inside an anonymous `struct`/`union` chain
 * under `root`), with cumulative byte offset `byteOffset` and flattened path
 * `fieldPath` from the start of `root`.
 */
predicate leafFieldOfRoot(Field f, Class root, int byteOffset, string fieldPath) {
  exists(Class declCls, int chainOffset, string chainPrefix |
    anonChain(declCls, root, chainOffset, chainPrefix) and
    f.getDeclaringType() = declCls and
    not f.getName().matches(["", "(unnamed%", "(unknown%"]) and
    not isAnonymousClass(f.getType().getUnderlyingType()) and
    byteOffset = chainOffset + f.getByteOffset() and
    fieldPath = chainPrefix + f.getName()
  )
}

/**
 * Computes the closing `};` line of a struct/union definition `s` from the
 * maximum end line of its direct and flattened leaf members.
 */
int structEndLine(Class s) {
  resolvedRootStruct(s, _, _) and
  if
    exists(Declaration m | m = s.getAMember() and m.getFile() = s.getFile()) or
    exists(Field f | leafFieldOfRoot(f, s, _, _) and f.getFile() = s.getFile())
  then
    result =
      max(int l |
        exists(Declaration m |
          m = s.getAMember() and m.getFile() = s.getFile() and l = m.getLocation().getEndLine()
        )
        or
        exists(Field f |
          leafFieldOfRoot(f, s, _, _) and
          f.getFile() = s.getFile() and
          l = f.getLocation().getEndLine()
        )
      ).maximum(s.getLocation().getEndLine()) + 1
  else result = s.getLocation().getEndLine()
}

/**
 * Holds if `f` is a trailing flexible-array member (`T arr[]`, `T arr[0]`, or
 * `T arr[1]`) of its declaring struct.
 */
predicate isFlexibleArrayField(Field f) {
  exists(Struct s |
    f = s.getCanonicalMember(max(int j | s.getCanonicalMember(j) instanceof Field | j))
  ) and
  f.getUnspecifiedType() instanceof ArrayType and
  (
    f.getUnspecifiedType().(ArrayType).getArraySize() <= 1 or
    not f.getUnspecifiedType().(ArrayType).hasArraySize()
  )
}

/**
 * Holds if `f` is a function pointer or array of function pointers.
 */
predicate isFuncPtrField(Field f) {
  f.getUnspecifiedType() instanceof FunctionPointerIshType or
  f.getUnspecifiedType().(ArrayType).getBaseType().getUnspecifiedType() instanceof
    FunctionPointerIshType
}

/**
 * Resolves `f` to its canonical enclosing root struct name, flattening
 * anonymous `struct`/`union` containers and `typedef struct { ... } name_t`
 * definitions. Used by both `structs.ql` and `field-acces-type.ql`.
 */
pragma[nomagic]
string canonicalStructName(Field f) {
  exists(Class decl | decl = f.getDeclaringType() |
    if resolvedRootStruct(decl, _, _)
    then resolvedRootStruct(decl, result, _)
    else
      if exists(Class root | anonClassParent+(decl, root) and resolvedRootStruct(root, _, _))
      then
        result =
          min(string sname |
            exists(Class root |
              anonClassParent+(decl, root) and resolvedRootStruct(root, sname, _)
            )
          )
      else result = decl.toString()
  )
}

/**
 * Resolves a `FieldAccess` `fa` to its canonical enclosing struct name,
 * falling back to the qualifier expression's underlying struct type when the
 * target field's declaring type is an unlinked anonymous struct/union.
 */
pragma[inline]
string canonicalFieldAccessParent(FieldAccess fa) {
  exists(string base | base = canonicalStructName(fa.getTarget()) |
    if base != "" and not base.matches("(unnamed%")
    then result = base
    else
      if
        exists(Type qt, Class c |
          qt = fa.getQualifier().getType().getUnderlyingType() and
          (c = qt or c = qt.(PointerType).getBaseType().getUnderlyingType()) and
          resolvedRootStruct(c, _, _)
        )
      then
        result =
          min(string sname |
            exists(Type qt, Class c |
              qt = fa.getQualifier().getType().getUnderlyingType() and
              (c = qt or c = qt.(PointerType).getBaseType().getUnderlyingType()) and
              resolvedRootStruct(c, sname, _)
            )
          )
      else result = base
  )
}
