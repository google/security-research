/**
 * @name allocs (allocation size/flag ranges)
 * @description For each kernel heap allocation (kmalloc family, matched by the
 *   __alloc_size attribute + gfp_t flags parameter -- version-robust across the
 *   6.10 _noprof macro refactor), emits the allocated type, object size, the
 *   VALUE RANGE of the allocation size and GFP flags (min/max), and the call
 *   location. Produces the `allocs` table consumed by the BTF prolog;
 *   kmalloc_dyn = (allocSizeMax <> allocSizeMin) marks variable-sized (elastic)
 *   objects.
 * @id cpp/dashboard/allocs
 * @kind table
 * @tags security kernel
 */

import cpp
import semmle.code.cpp.rangeanalysis.SimpleRangeAnalysis

// A trailing flexible-array member -- the structural signature of an "elastic"
// kernel object (variable-sized allocation).
class FlexibleArrayMember extends Field {
  FlexibleArrayMember() {
    exists(Struct s |
      this = s.getCanonicalMember(max(int j | s.getCanonicalMember(j) instanceof Field | j))
    ) and
    this.getUnspecifiedType() instanceof ArrayType and
    (
      this.getUnspecifiedType().(ArrayType).getArraySize() <= 1 or
      not this.getUnspecifiedType().(ArrayType).hasArraySize()
    )
  }
}

class AllocSizeAttribute extends GnuAttribute {
  AllocSizeAttribute() { this.getName() = "alloc_size" }
  int getArg0ParamOneBased() { result = this.getArgument(0).getValueInt() }
  int getArg1ParamOneBased() { result = this.getArgument(1).getValueInt() }
  predicate isSingleParamForm() { not exists(this.getArgument(1)) }
  predicate isTwoParamForm() { exists(this.getArgument(1)) }
}

// Percpu allocators also carry __alloc_size + gfp_t but are NOT kmalloc-cache
// objects, so the oracle excludes them; we do too.
predicate isExcludedAllocator(Function f) {
  f.getName().regexpMatch(
    ".*percpu.*|pcpu_alloc.*" +
    "|__vmalloc.*|vmalloc.*|__vcalloc.*" +
    "|alloc_pages.*" +
    "|__kmalloc.*" +
    "|kmalloc_array_node.*" +
    "|__do_krealloc.*"
  )
}

// Canonical 8-byte unsigned long type used for generic void* pointer arrays.
Type canonicalUnsignedLong() {
  result = max(IntegralType t | t.getName() = "unsigned long" | t order by t.getSize())
}

// Top-level helpers (outside KmallocCall to avoid unbound `this` Cartesian product)
Type sizeofParamRaw(Expr e) {
  result = e.(SizeofExprOperator).getExprOperand().getFullyConverted().getType()
  or
  result = e.(SizeofTypeOperator).getTypeOperand()
}

// Strip one pointer level from sizeof(T*). When T is void (sizeof(void*)),
// report unsigned long (8 bytes) matching the 6.1.111 oracle.
Type sizeofParam(Expr e) {
  exists(Type raw, Type u | raw = sizeofParamRaw(e) and u = raw.getUnspecifiedType() |
    u instanceof PointerType and
    (
      if u.(PointerType).getBaseType().getUnspecifiedType() instanceof VoidType
      then result = canonicalUnsignedLong()
      else result = u.(PointerType).getBaseType()
    )
    or
    not u instanceof PointerType and
    result = raw
  )
}

// Normalize type: decay arrays to element type, strip pointers to pointee,
// but preserve generic void* pointers as 8-byte unsigned long.
Type normalizeType(Type raw) {
  exists(Type u | u = raw.getUnspecifiedType() |
    u instanceof ArrayType and
    result = normalizeType(u.(ArrayType).getBaseType())
    or
    u instanceof PointerType and
    (
      if u.(PointerType).getBaseType().getUnspecifiedType() instanceof VoidType
      then result = canonicalUnsignedLong()
      else result = normalizeType(u.(PointerType).getBaseType())
    )
    or
    not u instanceof ArrayType and not u instanceof PointerType and
    result = u
  )
}

int pointerDepth(Type t) {
  exists(Type u | u = t.getUnspecifiedType() |
    if u instanceof PointerType
    then result = 1 + pointerDepth(u.(PointerType).getBaseType())
    else if u instanceof ArrayType
    then result = 1 + pointerDepth(u.(ArrayType).getBaseType())
    else result = 0
  )
}

Location canonicalTypeLocation(Type t) {
  result =
    min(Location l |
      l = t.getLocation() and exists(l.getFile().getRelativePath())
    |
      l
      order by
        l.getFile().getRelativePath() asc, l.getStartLine() asc, l.getStartColumn() asc
    )
}

string getTypeUri(Type t) {
  if exists(canonicalTypeLocation(t))
  then result = canonicalTypeLocation(t).getFile().getRelativePath()
  else result = "file:/"
}

string getTypeStartLine(Type t) {
  if exists(canonicalTypeLocation(t))
  then result = canonicalTypeLocation(t).getStartLine().toString()
  else result = ""
}

string getTypeStartCol(Type t) {
  if exists(canonicalTypeLocation(t))
  then result = canonicalTypeLocation(t).getStartColumn().toString()
  else result = ""
}

// Step upward through statement parents and across StmtExpr ({ ... }) boundaries.
Stmt enclosingStmtStep(Stmt s) {
  result = s.getParentStmt()
  or
  exists(StmtExpr se | se.getStmt() = s and result = se.getEnclosingStmt())
}

class KmallocCall extends FunctionCall {
  int sizeArgIndex;
  int flagsArgIndex;

  KmallocCall() {
    exists(this.getEnclosingStmt()) and
    not isExcludedAllocator(this.getTarget()) and
    // Exclude the unevaluated typeof(_do_alloc) _res declaration and the dead/duplicate
    // then-branch of 6.10+ alloc_hooks_tag (keeping the reachable else-branch):
    //   typeof(_do_alloc) _res;
    //   if (mem_alloc_profiling_enabled()) { _res = _do_alloc; } else _res = _do_alloc;
    not exists(DeclStmt ds |
      ds.getADeclaration().hasName("_res") and
      ds = enclosingStmtStep*(this.getEnclosingStmt())
    ) and
    not exists(IfStmt ifs |
      ifs.getCondition().(FunctionCall).getTarget().hasName("mem_alloc_profiling_enabled") and
      ifs.getThen() = enclosingStmtStep*(this.getEnclosingStmt())
    ) and
    exists(Parameter p |
      p = this.getTarget().getParameter(flagsArgIndex) and
      p.getType().hasName("gfp_t")
    ) and
    exists(AllocSizeAttribute attr | attr = this.getTarget().getAnAttribute() |
      attr.isSingleParamForm() and
      sizeArgIndex = attr.getArg0ParamOneBased() - 1
      or
      attr.isTwoParamForm() and
      sizeArgIndex = attr.getArg1ParamOneBased() - 1
    )
  }

  Expr getSizeArg() { result = this.getArgument(sizeArgIndex) }
  Expr getFlagsArg() { result = this.getArgument(flagsArgIndex) }

  // For 2-parameter array allocators (__alloc_size(1, 2): kcalloc, kmalloc_array, kvcalloc),
  // return the element count argument (arg0).
  Expr getCountArg() {
    exists(AllocSizeAttribute attr |
      attr = this.getTarget().getAnAttribute() and
      attr.isTwoParamForm() and
      result = this.getArgument(attr.getArg0ParamOneBased() - 1)
    )
  }

  // Upward AST step from kmalloc_noprof to enclosing alloc_hooks_tag StmtExpr:
  //   else-branch: this -> ExprStmt -> IfStmt -> BlockStmt -> StmtExpr (2 hops)
  //   then-branch: this -> ExprStmt -> BlockStmt -> IfStmt -> BlockStmt -> StmtExpr (3 hops)
  StmtExpr innerAllocHooks() {
    result.getStmt() = this.getEnclosingStmt().getParentStmt().getParentStmt() or
    result.getStmt() = this.getEnclosingStmt().getParentStmt().getParentStmt().getParentStmt()
  }

  // Upward AST step from innerAllocHooks to outer alloc_hooks StmtExpr:
  //   innerAllocHooks -> ExprStmt -> BlockStmt -> StmtExpr
  StmtExpr outerAllocHooks() {
    result.getStmt() = this.innerAllocHooks().getEnclosingStmt().getParentStmt()
  }

  // Upward AST step from outerAllocHooks to 6.12+/6.18 __alloc_objs / __alloc_flex StmtExpr:
  StmtExpr allocObjsWrapper() {
    result.getStmt() = this.outerAllocHooks().getEnclosingStmt().getParentStmt() or
    result.getStmt() = this.outerAllocHooks().getEnclosingStmt().getParentStmt().getParentStmt()
  }

  // Candidate wrapper expressions (from innermost call to outermost macro StmtExpr).
  Expr getWrapperExpr() {
    result = this or
    result = this.innerAllocHooks() or
    result = this.outerAllocHooks() or
    result = this.allocObjsWrapper()
  }

  // Outermost expression wrapping this allocation call.
  Expr getOuterExpr() {
    if exists(this.allocObjsWrapper()) then result = this.allocObjsWrapper()
    else if exists(this.outerAllocHooks()) then result = this.outerAllocHooks()
    else if exists(this.innerAllocHooks()) then result = this.innerAllocHooks()
    else result = this
  }

  // Extraction of target pointer type from surrounding cast, assignment, or initializer
  // at any wrapper level (direct call, alloc_hooks, or __alloc_objs / __alloc_flex).
  Type getContextTargetType() {
    exists(Expr outer, Expr fc |
      outer = this.getWrapperExpr() and
      fc = outer.getFullyConverted()
    |
      result = fc.getType()
      or
      result = fc.getParent().(AssignExpr).getLValue().getType()
      or
      result = outer.getParent().(AssignExpr).getLValue().getType()
      or
      result = fc.getParent().(Initializer).getDeclaration().(Variable).getType()
      or
      result = outer.getParent().(Initializer).getDeclaration().(Variable).getType()
      or
      result = fc.getParent().(ReturnStmt).getEnclosingFunction().getType()
      or
      result = outer.getParent().(ReturnStmt).getEnclosingFunction().getType()
    )
  }

  Type getNonVoidContextTargetType() {
    result = this.getContextTargetType() and
    not (
      result.getUnspecifiedType() instanceof PointerType and
      result.getUnspecifiedType().(PointerType).getBaseType().getUnspecifiedType() instanceof VoidType
    ) and
    not result.getUnspecifiedType() instanceof VoidType
  }

  Type getBestOuterType() {
    if exists(this.getNonVoidContextTargetType())
    then
      result =
        min(Type t |
          t = this.getNonVoidContextTargetType()
        |
          t order by pointerDepth(t) desc, t.getSize() desc, t.getName() asc
        )
    else result = this.getOuterExpr().getFullyConverted().getType()
  }

  // Assigned/cast pointer type with one level of pointer indirection removed.
  Type assignedPointeeType() {
    exists(Type raw, Type u | raw = this.getBestOuterType() and u = raw.getUnspecifiedType() |
      u instanceof PointerType and
      result = u.(PointerType).getBaseType()
      or
      not u instanceof PointerType and
      result = raw
    )
  }

  Expr sizeSubExpr() {
    result = this.getSizeArg().getAChild*()
    or
    result = this.getSizeArg().(VariableAccess).getTarget().getInitializer().getExpr().getAChild*()
  }

  // Valid sizeof candidate: excludes bare void, zero-size structs, unnamed
  // anonymous structs from BUILD_BUG_ON_ZERO, and (for depth<=1) bit-layout structs larger than constSize().
  Type validSizeofCandidate() {
    exists(Expr sof |
      sof = this.sizeSubExpr() and
      result = normalizeType(sizeofParam(sof)) and
      not result instanceof VoidType and
      result.getSize() > 0 and
      not result.getName().matches("%unnamed%") and
      (
        pointerDepth(this.getBestOuterType()) >= 2 or
        not this.sizeIsConstant() or
        result.getSize() <= this.constSize()
      )
    )
  }

  // Rank candidates to deterministically select a single canonical type per site:
  //   1: sizeof candidate matching the assigned pointer target type
  //   2: sizeof candidate that is a Struct with a FlexibleArrayMember
  //   3: sizeof candidate that is a named Struct/Class
  //   4: assigned pointer target type that is a named Struct/Class
  //   5: any other valid sizeof candidate (e.g. unsigned long, int)
  //   6: fallback to assignedPointeeType()
  int candidateRank(Type t) {
    t = this.validSizeofCandidate() and
    t = normalizeType(this.assignedPointeeType()) and
    result = 1
    or
    t = this.validSizeofCandidate() and
    t.(Struct).getAField() instanceof FlexibleArrayMember and
    result = 2
    or
    t = this.validSizeofCandidate() and
    t instanceof Class and
    result = 3
    or
    t = normalizeType(this.assignedPointeeType()) and
    t instanceof Class and
    t.getSize() > 0 and
    not t.getName().matches("%unnamed%") and
    (
      pointerDepth(this.getBestOuterType()) >= 2 or
      not this.sizeIsConstant() or
      t.getSize() <= this.constSize()
    ) and
    result = 4
    or
    t = this.validSizeofCandidate() and
    not t instanceof Class and
    result = 5
    or
    not exists(this.validSizeofCandidate()) and
    t = normalizeType(this.assignedPointeeType()) and
    result = 6
  }

  // Select single canonical type per allocation site using a single stratification pass.
  Type rawAllocType() {
    result =
      min(Type t, int prio |
        prio = this.candidateRank(t)
      |
        t
        order by
          prio asc, t.getSize() desc, t.getName() asc, getTypeUri(t) asc,
          getTypeStartLine(t) asc, getTypeStartCol(t) asc
      )
  }

  Type getAllocType() {
    if
      pointerDepth(this.getBestOuterType()) <= 1 and
      this.totalSizeHi() > 0 and
      this.rawAllocType().getSize() > this.totalSizeHi()
    then result = canonicalUnsignedLong()
    else result = this.rawAllocType()
  }

  // Recover user-facing allocator name without expensive cross-table location joins.
  string getCleanCallName() {
    exists(string rawName | rawName = this.getTarget().getName().regexpReplaceAll("_noprof$", "") |
      if rawName = "__kvmalloc_node"
      then
        if this.getFlagsArg().getValue().toInt().bitAnd(256) != 0
        then result = "kvzalloc"
        else result = "kvmalloc"
      else if rawName = "kvmalloc_array_node"
      then result = "kvmalloc_array"
      else result = rawName
    )
  }

  predicate sizeIsConstant() { exists(this.getSizeArg().getValue()) }
  float constSize() { result = this.getSizeArg().getValue().toFloat() }

  float elemSizeLo() {
    if this.sizeIsConstant() then result = this.constSize()
    else result = lowerBound(this.getSizeArg().getFullyConverted())
  }

  float elemSizeHi() {
    if this.sizeIsConstant() then result = this.constSize()
    else result = upperBound(this.getSizeArg().getFullyConverted())
  }

  predicate countIsConstant() { exists(this.getCountArg().getValue()) }
  float constCount() { result = this.getCountArg().getValue().toFloat() }

  float countLo() {
    if this.countIsConstant()
    then result = this.constCount()
    else
      // Real slab allocations have count >= 1 (count == 0 returns ZERO_SIZE_PTR).
      exists(float lb | lb = lowerBound(this.getCountArg().getFullyConverted()) |
        if lb < 1.0 then result = 1.0 else result = lb
      )
  }

  float countHi() {
    if this.countIsConstant()
    then result = this.constCount()
    else
      exists(float ub, float lb |
        ub = upperBound(this.getCountArg().getFullyConverted()) and
        lb = this.countLo()
      |
        if ub < lb then result = lb else result = ub
      )
  }

  float totalSizeLo() {
    if exists(this.getCountArg())
    then result = this.countLo() * this.elemSizeLo()
    else result = this.elemSizeLo()
  }

  float totalSizeHi() {
    if exists(this.getCountArg())
    then result = this.countHi() * this.elemSizeHi()
    else result = this.elemSizeHi()
  }

  predicate flagsIsConstant() { exists(this.getFlagsArg().getValue()) }
  float constFlags() { result = this.getFlagsArg().getValue().toFloat() }

  float totalFlagsLo() {
    if this.flagsIsConstant() then result = this.constFlags()
    else result = lowerBound(this.getFlagsArg().getFullyConverted())
  }

  float totalFlagsHi() {
    if this.flagsIsConstant() then result = this.constFlags()
    else result = upperBound(this.getFlagsArg().getFullyConverted())
  }
}

bindingset[lo, hi]
string valueOrVariable(float lo, float hi) {
  if lo = hi then result = lo.toString() else result = "variable"
}

string isFlexibleType(Type t) {
  if t.(Struct).getAField() instanceof FlexibleArrayMember
  then result = "true"
  else result = "false"
}

from KmallocCall kfc, Type allocType, float sizeLo, float sizeHi, float flagLo, float flagHi
where
  allocType = kfc.getAllocType() and
  sizeLo = kfc.totalSizeLo() and
  sizeHi = kfc.totalSizeHi() and
  flagLo = kfc.totalFlagsLo() and
  flagHi = kfc.totalFlagsHi()
select
  kfc.getCleanCallName() as call_value,
  allocType.getName() as type_value,
  allocType.getSize().toString() as objectSize,
  sizeLo.toString() as sizeMin,
  sizeHi.toString() as sizeMax,
  valueOrVariable(sizeLo, sizeHi) as sizeVal,
  flagLo.toString() as flagsMin,
  flagHi.toString() as flagsMax,
  valueOrVariable(flagLo, flagHi) as flagsVal,
  kfc.getLocation().getFile().getRelativePath() as file,
  kfc.getLocation().getStartLine().toString() as line,
  kfc.getLocation().getStartColumn().toString() as col,
  isFlexibleType(allocType) as isFlexible,
  pointerDepth(kfc.getBestOuterType()).toString() as depth,
  getTypeUri(allocType) as typeUri,
  getTypeStartLine(allocType) as typeLine,
  getTypeStartCol(allocType) as typeCol
