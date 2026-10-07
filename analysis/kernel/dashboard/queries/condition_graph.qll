/**
 * Shared CodeQL library for `condition-graph-direct.ql` and `condition-graph-all.ql`.
 *
 * Extracts capability gates (`capable`, `ns_capable`), subsystem capability wrappers,
 * single-return capability helper functions, declarative Generic Netlink permission
 * flags (`GENL_ADMIN_PERM`, `GENL_UNS_ADMIN_PERM`), `sysctl` tables, and `module_param`
 * guards, along with branch-polarity-aware controlled call sites and line spans.
 */

import cpp

/** Holds if `expr` references `init_user_ns` or `init_net` directly or via a local variable. */
pragma[inline]
predicate isInitUserNsExpr(Expr expr) {
  exists(VariableAccess va | va = expr.getAChild*() |
    va.getTarget().getName() in ["init_user_ns", "init_net"]
    or
    exists(StackVariable sv, Expr init |
      sv = va.getTarget() and
      (
        init = sv.getInitializer().getExpr()
        or
        exists(AssignExpr ae |
          ae.getEnclosingFunction() = expr.getEnclosingFunction() and
          ae.getLValue() = sv.getAnAccess() and
          init = ae.getRValue()
        )
      ) and
      exists(VariableAccess va2 | va2 = init.getAChild*() |
        va2.getTarget().getName() in ["init_user_ns", "init_net"]
      )
    )
  )
}

/** Classifies the user-namespace kind referenced by `nsExpr`. */
pragma[inline]
string classifyNsScope(Expr nsExpr) {
  if isInitUserNsExpr(nsExpr)
  then result = "init_user_ns"
  else
    if
      exists(FieldAccess fa | fa = nsExpr.getAChild*() |
        fa.getTarget().getName() in ["s_user_ns", "i_sb"]
      )
    then result = "s_user_ns"
    else
      if
        exists(FieldAccess fa | fa = nsExpr.getAChild*() |
          fa.getTarget().getName() in ["mnt_ns", "mnt_userns"]
        )
      then result = "mnt_ns"
      else
        if
          exists(VariableAccess va | va = nsExpr.getAChild*() |
            va.getTarget().getType().getUnspecifiedType().(PointerType).getBaseType().getName() in [
                "net", "sock", "sk_buff", "socket", "netlink_skb_parms"
              ]
          )
        then result = "net_ns"
        else
          if
            exists(FieldAccess fa | fa = nsExpr.getAChild*() |
              fa.getTarget().getName() = "f_cred"
            )
          then result = "f_cred"
          else result = "user_ns"
}

/** Names of capability wrapper functions whose internal bodies should not duplicate caller sites. */
predicate isCapabilityWrapperFunction(Function f) {
  f.getName() in [
      "capable", "ns_capable", "ns_capable_noaudit", "ns_capable_setid",
      "ns_capable_common", "file_ns_capable", "capable_wrt_inode_uidgid",
      "privileged_wrt_inode_uidgid", "inode_owner_or_capable",
      "in_group_or_capable", "has_capability", "has_capability_noaudit",
      "has_ns_capability", "has_ns_capability_noaudit", "netlink_capable",
      "netlink_net_capable", "netlink_ns_capable", "__netlink_ns_capable",
      "sk_capable", "sk_net_capable", "sk_ns_capable", "sockopt_capable",
      "sockopt_ns_capable", "bpf_capable", "perfmon_capable",
      "checkpoint_restore_ns_capable", "mount_capable", "may_mount",
      "ptracer_capable", "ptrace_has_cap", "rtnl_get_net_ns_capable",
      "rtnl_link_get_net_capable", "netlink_allowed"
    ]
}

/**
 * Holds if `sub` is a positive conjunction subexpression of `root`
 * (so `root == true` unconditionally requires `sub == true`).
 */
predicate unconditionalPosGuardSubExpr(Expr root, Expr sub) {
  sub = root
  or
  exists(ParenthesisExpr pe |
    unconditionalPosGuardSubExpr(root, pe) and
    sub = pe.getExpr()
  )
  or
  exists(LogicalAndExpr land |
    unconditionalPosGuardSubExpr(root, land) and
    sub = land.getAnOperand()
  )
}

/**
 * Holds if `fc` is a direct capability call or enumerated subsystem capability
 * wrapper call with classified `gateType` ("capable" or "ns_capable"), `capArg`,
 * and `nsScope`.
 */
pragma[nomagic]
predicate baseCapabilityCallInfo(
  FunctionCall fc, string gateType, string capArg, string nsScope
) {
  exists(string fn | fn = fc.getTarget().getName() |
    // 1. Direct global capable(cap) and sockopt_capable(cap)
    fn in ["capable", "sockopt_capable"] and
    gateType = "capable" and
    capArg = fc.getArgument(0).toString() and
    nsScope = "init_user_ns"
    or
    // 2. Global capability wrappers with cap at argument 1
    fn in [
        "netlink_capable", "sk_capable", "has_capability",
        "has_capability_noaudit"
      ] and
    gateType = "capable" and
    capArg = fc.getArgument(1).toString() and
    nsScope = "init_user_ns"
    or
    // 3. Global capability wrappers with fixed capability
    fn = "bpf_capable" and
    gateType = "capable" and
    capArg = "CAP_BPF" and
    nsScope = "init_user_ns"
    or
    fn = "perfmon_capable" and
    gateType = "capable" and
    capArg = "CAP_PERFMON" and
    nsScope = "init_user_ns"
    or
    // 4. 2-arg namespace capability checks: (ns, cap)
    fn in [
        "ns_capable", "ns_capable_noaudit", "ns_capable_setid",
        "ns_capable_common", "sockopt_ns_capable"
      ] and
    capArg = fc.getArgument(1).toString() and
    nsScope = classifyNsScope(fc.getArgument(0)) and
    (
      if isInitUserNsExpr(fc.getArgument(0))
      then gateType = "capable"
      else gateType = "ns_capable"
    )
    or
    // 5. 3-arg namespace capability checks: (obj, ns, cap)
    fn in [
        "file_ns_capable", "netlink_ns_capable", "__netlink_ns_capable",
        "sk_ns_capable", "has_ns_capability", "has_ns_capability_noaudit"
      ] and
    capArg = fc.getArgument(2).toString() and
    nsScope = classifyNsScope(fc.getArgument(1)) and
    (
      if isInitUserNsExpr(fc.getArgument(1))
      then gateType = "capable"
      else gateType = "ns_capable"
    )
    or
    // 6. Net-namespace capability wrappers
    fn in ["netlink_net_capable", "sk_net_capable"] and
    capArg = fc.getArgument(1).toString() and
    nsScope = "net_ns" and
    gateType = "ns_capable"
    or
    fn = "rtnl_link_get_net_capable" and
    capArg = fc.getArgument(3).toString() and
    nsScope = classifyNsScope(fc.getArgument(1)) and
    (
      if isInitUserNsExpr(fc.getArgument(1))
      then gateType = "capable"
      else gateType = "ns_capable"
    )
    or
    // 7. VFS / inode capability wrappers
    fn = "capable_wrt_inode_uidgid" and
    capArg = fc.getArgument(fc.getNumberOfArguments() - 1).toString() and
    nsScope = "s_user_ns" and
    gateType = "ns_capable"
    or
    fn in ["privileged_wrt_inode_uidgid", "inode_owner_or_capable"] and
    capArg = "CAP_FOWNER" and
    nsScope = "s_user_ns" and
    gateType = "ns_capable"
    or
    fn = "in_group_or_capable" and
    capArg = "CAP_FSETID" and
    nsScope = "s_user_ns" and
    gateType = "ns_capable"
    or
    // 8. Fixed-capability namespace helpers
    fn = "checkpoint_restore_ns_capable" and
    capArg = "CAP_CHECKPOINT_RESTORE" and
    nsScope = classifyNsScope(fc.getArgument(0)) and
    (
      if isInitUserNsExpr(fc.getArgument(0))
      then gateType = "capable"
      else gateType = "ns_capable"
    )
    or
    fn = "mount_capable" and
    capArg = "CAP_SYS_ADMIN" and
    nsScope = "s_user_ns" and
    gateType = "ns_capable"
    or
    fn = "may_mount" and
    capArg = "CAP_SYS_ADMIN" and
    nsScope = "mnt_ns" and
    gateType = "ns_capable"
    or
    fn = "ptracer_capable" and
    capArg = "CAP_SYS_PTRACE" and
    nsScope = classifyNsScope(fc.getArgument(1)) and
    (
      if isInitUserNsExpr(fc.getArgument(1))
      then gateType = "capable"
      else gateType = "ns_capable"
    )
    or
    fn = "ptrace_has_cap" and
    capArg = "CAP_SYS_PTRACE" and
    nsScope = classifyNsScope(fc.getArgument(0)) and
    (
      if isInitUserNsExpr(fc.getArgument(0))
      then gateType = "capable"
      else gateType = "ns_capable"
    )
    or
    fn in ["rtnl_get_net_ns_capable", "netlink_allowed"] and
    capArg = "CAP_NET_ADMIN" and
    nsScope = "net_ns" and
    gateType = "ns_capable"
  )
}

/**
 * Holds if `f` is a custom capability helper function that unconditionally
 * requires `innerFc` to return `true`:
 * 1. Single-return helper whose return expression is `innerFc` or a conjunction
 *    `innerFc && ...` (e.g., `may_setgroups`, `tcp_can_repair_sock`), or
 * 2. Multi-statement `bool` permission helper with an early `if (!innerFc) return false;`
 *    guard before any `return true;` path (`if (!capable(A)) return false; ... return check();`).
 */
pragma[nomagic]
predicate singleReturnCapabilityHelper(
  Function f, string gateType, string capArg, string nsScope
) {
  not isCapabilityWrapperFunction(f) and
  exists(FunctionCall innerFc |
    innerFc.getEnclosingFunction() = f and
    baseCapabilityCallInfo(innerFc, gateType, capArg, nsScope) and
    not capArg = f.getAParameter().getName() and
    (
      count(ReturnStmt r | r.getEnclosingFunction() = f) = 1 and
      exists(ReturnStmt ret |
        ret.getEnclosingFunction() = f and
        unconditionalPosGuardSubExpr(ret.getExpr(), innerFc)
      )
      or
      f.getUnspecifiedType().toString() in ["bool", "_Bool"] and
      count(ReturnStmt r | r.getEnclosingFunction() = f) <= 6 and
      exists(IfStmt guardIf, ReturnStmt abortRet, NotExpr ne |
        guardIf.getEnclosingFunction() = f and
        abortRet.getEnclosingStmt*() = guardIf.getThen() and
        abortRet.getExpr().getValue() = "0" and
        unconditionalPosGuardSubExpr(guardIf.getCondition(), ne) and
        unconditionalPosGuardSubExpr(ne.getOperand(), innerFc) and
        not exists(ReturnStmt priorRet |
          priorRet.getEnclosingFunction() = f and
          priorRet.getLocation().getStartLine() <
            guardIf.getLocation().getStartLine() and
          not priorRet.getExpr().getValue() = "0"
        )
      )
    )
  )
}

/**
 * Holds if `fc` is a capability or permission helper call with classified
 * `gateType` ("capable" or "ns_capable"), `capArg`, and `nsScope`.
 */
pragma[nomagic]
predicate capabilityCallInfo(
  FunctionCall fc, string gateType, string capArg, string nsScope
) {
  not isCapabilityWrapperFunction(fc.getEnclosingFunction()) and
  not singleReturnCapabilityHelper(fc.getEnclosingFunction(), _, _, _) and
  (
    baseCapabilityCallInfo(fc, gateType, capArg, nsScope)
    or
    singleReturnCapabilityHelper(fc.getTarget(), gateType, capArg, nsScope)
  )
}

/**
 * Holds if `e` is a disjunction subexpression of `root`
 * (so `root == false` unconditionally requires `e == false`).
 */
predicate unconditionalDisjSubExpr(Expr root, Expr e) {
  e = root
  or
  exists(ParenthesisExpr pe |
    unconditionalDisjSubExpr(root, pe) and
    e = pe.getExpr()
  )
  or
  exists(LogicalOrExpr lor |
    unconditionalDisjSubExpr(root, lor) and
    e = lor.getAnOperand()
  )
  or
  exists(LogicalAndExpr land |
    unconditionalDisjSubExpr(root, land) and
    e = land.getAnOperand() and
    forall(Expr op | op = land.getAnOperand() |
      exists(CapabilityConditionCall c | c = op.getAChild*())
    )
  )
}

/**
 * Holds if `sub` is a negated guard subexpression of `root`
 * (so `root == false` unconditionally requires `sub == true`).
 */
predicate unconditionalNegGuardSubExpr(Expr root, Expr sub) {
  exists(NotExpr ne |
    unconditionalDisjSubExpr(root, ne) and
    unconditionalPosGuardSubExpr(ne.getOperand(), sub)
  )
  or
  exists(EQExpr eq |
    unconditionalDisjSubExpr(root, eq) and
    eq.getAnOperand().getValue() = "0" and
    unconditionalPosGuardSubExpr(eq.getAnOperand(), sub)
  )
}

/** Holds if `sub` is under a logical negation (`!` or `== 0`) inside `root`. */
pragma[inline]
predicate isExprNegatedIn(Expr sub, Expr root) {
  exists(NotExpr ne |
    ne = root.getAChild*() and
    ne.getOperand().getAChild*() = sub
  )
  or
  exists(EQExpr eq |
    eq = root.getAChild*() and
    eq.getAnOperand().getAChild*() = sub and
    eq.getAnOperand().getValue() = "0"
  )
}

abstract class InterestingConditionCalls extends Element {
  abstract string getInterestingType();
  abstract string getInterestingArgString();
  abstract string getInterestingLocationString();

  string getNsScope() { result = "" }
}

class CapabilityConditionCall extends InterestingConditionCalls, FunctionCall {
  string gateType;
  string capArg;
  string nsScope;

  CapabilityConditionCall() {
    capabilityCallInfo(this, gateType, capArg, nsScope)
  }

  override string getInterestingType() { result = gateType }

  override string getInterestingArgString() { result = capArg }

  pragma[nomagic]
  override string getInterestingLocationString() {
    result = this.(FunctionCall).getLocation().toString()
  }

  override string getNsScope() { result = nsScope }
}

class ModuleParam extends InterestingConditionCalls, MacroInvocation {
  ModuleParam() { this.getMacroName() = "module_param" }

  override string getInterestingType() { result = "module_param" }

  pragma[nomagic]
  private VariableAccess getModuleParamAffectedElement() {
    inmacroexpansion(unresolveElement(result), underlyingElement(this))
    or
    macrolocationbind(underlyingElement(this), result.getLocation())
  }

  pragma[nomagic]
  Variable getTargetVariable() {
    result = this.getModuleParamAffectedElement().getTarget() and
    not result.getName().regexpMatch("param_ops.*|__param_str.*")
  }

  override string getInterestingArgString() {
    result = this.getTargetVariable().getName()
  }

  pragma[nomagic]
  override string getInterestingLocationString() {
    result = this.(MacroInvocation).getLocation().toString()
  }
}

class SysCtl extends InterestingConditionCalls, ClassAggregateLiteral {
  SysCtl() { this.getType().getName() = "ctl_table" }

  override string getInterestingType() { result = "sysctl" }

  pragma[nomagic]
  Variable getTargetVariable() {
    exists(Field f |
      f.getName() = "data" and
      result = this.getAFieldExpr(f).(AddressOfExpr).getAddressable()
    )
  }

  override string getInterestingArgString() {
    result = this.getTargetVariable().getName()
  }

  pragma[nomagic]
  override string getInterestingLocationString() {
    result = this.(ClassAggregateLiteral).getLocation().toString()
  }
}

/**
 * Materializes the link between `ic` and its guarding `IfStmt` `ifst`,
 * along with `isNegated` (true when the `then` branch is the failure/abort branch).
 */
pragma[nomagic]
predicate conditionGuardIfStmt(
  InterestingConditionCalls ic, IfStmt ifst, boolean isNegated
) {
  exists(CapabilityConditionCall cap | cap = ic |
    unconditionalNegGuardSubExpr(ifst.getCondition(), cap) and
    isNegated = true
    or
    unconditionalPosGuardSubExpr(ifst.getCondition(), cap) and
    isNegated = false
  )
  or
  exists(
    CapabilityConditionCall cap, StackVariable sv, Expr defExpr,
    VariableAccess condVa
  |
    cap = ic and
    sv.getFunction() = cap.getEnclosingFunction() and
    ifst.getEnclosingFunction() = cap.getEnclosingFunction() and
    (
      defExpr = sv.getInitializer().getExpr()
      or
      exists(AssignExpr ae |
        ae.getLValue() = sv.getAnAccess() and
        defExpr = ae.getRValue()
      )
    ) and
    condVa = sv.getAnAccess() and
    (
      unconditionalPosGuardSubExpr(defExpr, cap) and
      (
        unconditionalNegGuardSubExpr(ifst.getCondition(), condVa) and
        isNegated = true
        or
        unconditionalPosGuardSubExpr(ifst.getCondition(), condVa) and
        isNegated = false
      )
      or
      unconditionalNegGuardSubExpr(defExpr, cap) and
      (
        unconditionalDisjSubExpr(ifst.getCondition(), condVa) and
        isNegated = true
        or
        unconditionalNegGuardSubExpr(ifst.getCondition(), condVa) and
        isNegated = false
      )
    )
  )
  or
  exists(Variable v, VariableAccess va |
    (
      v = ic.(ModuleParam).getTargetVariable()
      or
      v = ic.(SysCtl).getTargetVariable()
    ) and
    va = v.getAnAccess() and
    ifst.getCondition().getAChild() = va and
    if isExprNegatedIn(va, ifst.getCondition())
    then isNegated = true
    else isNegated = false
  )
}

/** Holds if `ifst`'s `then` branch aborts normal execution via return, break, continue, or goto. */
pragma[nomagic]
predicate thenBranchHasAbort(IfStmt ifst) {
  conditionGuardIfStmt(_, ifst, _) and
  (
    exists(ReturnStmt ret | ret = ifst.getThen().getAChild*())
    or
    exists(BreakStmt brk | brk = ifst.getThen().getAChild*())
    or
    exists(ContinueStmt cont | cont = ifst.getThen().getAChild*())
    or
    exists(GotoStmt gs | gs = ifst.getThen().getAChild*())
  )
}

/** Holds if `ifst`'s `then` branch jumps to a label at `labelLine`. */
pragma[nomagic]
predicate thenBranchGotoLabelLine(IfStmt ifst, int labelLine) {
  exists(GotoStmt gs, LabelStmt ls |
    conditionGuardIfStmt(_, ifst, _) and
    gs = ifst.getThen().getAChild*() and
    ls.getName() = gs.getName() and
    ls.getEnclosingFunction() = ifst.getEnclosingFunction() and
    labelLine = ls.getLocation().getStartLine()
  )
}

/** Computes the next `SwitchCase` start line after `ifst` when `ifst` is inside a `SwitchStmt`. */
pragma[nomagic]
predicate nextSwitchCaseLine(IfStmt ifst, int nextCaseLine) {
  conditionGuardIfStmt(_, ifst, _) and
  exists(SwitchStmt sw |
    sw.getStmt() = ifst.getParent() and
    nextCaseLine =
      min(SwitchCase sc |
        sc.getSwitchStmt() = sw and
        sc.getLocation().getStartLine() > ifst.getLocation().getStartLine()
      |
        sc.getLocation().getStartLine()
      )
  )
}

/** Computes the upper bound line `boundLine` for an early-abort `ifst` within its enclosing block. */
pragma[nomagic]
predicate abortGuardEndLine(IfStmt ifst, int boundLine) {
  thenBranchHasAbort(ifst) and
  exists(int parentEnd |
    parentEnd = ifst.getParent().getLocation().getEndLine() and
    if exists(int ncl | nextSwitchCaseLine(ifst, ncl))
    then
      exists(int ncl | nextSwitchCaseLine(ifst, ncl) |
        boundLine = (ncl - 1).minimum(parentEnd)
      )
    else
      if exists(int ll | thenBranchGotoLabelLine(ifst, ll) and ll > ifst.getLocation().getEndLine())
      then
        exists(int ll |
          ll = min(int l | thenBranchGotoLabelLine(ifst, l) and l > ifst.getLocation().getEndLine())
        |
          boundLine = (ll - 1).minimum(parentEnd)
        )
      else boundLine = parentEnd
  )
}

/**
 * Computes the controlled line span `[minLine, maxLine]` for `(ic, ifst)`.
 *
 * Caveats on the single-interval `[minLine, maxLine]` approximation:
 * - For negated early-abort guards (`if (!capable(...)) return/goto`), `maxLine`
 *   is bounded by the earliest forward `goto` target label (`min(labelLine) - 1`),
 *   the next `case`/`default` label in an enclosing `switch`, or the end of the
 *   enclosing block. If a `then` branch contains multiple `goto` targets, using
 *   `min(labelLine)` is a conservative lower bound on the guarded region.
 * - Because control dependence is represented as a single contiguous line
 *   interval `[minLine, maxLine]`, complex intra-procedural control flow such as
 *   backward jumps or nested re-gating within the same block is approximated by
 *   source line containment rather than full basic-block post-dominance.
 */
pragma[nomagic]
predicate conditionGuardSpan(
  InterestingConditionCalls ic, IfStmt ifst, int minLine, int maxLine
) {
  exists(boolean isNegated |
    conditionGuardIfStmt(ic, ifst, isNegated) and
    (
      // 1. Negated guard with early abort: `if (!capable(...)) return -EPERM;`
      isNegated = true and
      abortGuardEndLine(ifst, maxLine) and
      minLine = ifst.getLocation().getStartLine() and
      maxLine >= minLine
      or
      // 2. Negated guard with else branch (non-aborting then): `if (!capable(...)) { ... } else { ... }`
      isNegated = true and
      not thenBranchHasAbort(ifst) and
      exists(ifst.getElse()) and
      minLine = ifst.getElse().getLocation().getStartLine() and
      maxLine = ifst.getElse().getLocation().getEndLine()
      or
      // 3. Positive capability guard: `if (capable(...)) { ... }`
      isNegated = false and
      ic instanceof CapabilityConditionCall and
      minLine = ifst.getThen().getLocation().getStartLine() and
      maxLine = ifst.getThen().getLocation().getEndLine()
      or
      // 4. ModuleParam / SysCtl guard: encloses from ifst to end of parent block
      (ic instanceof ModuleParam or ic instanceof SysCtl) and
      minLine = ifst.getLocation().getStartLine() and
      maxLine = ifst.getParent().getLocation().getEndLine()
    )
  )
}

/** Materializes `Call`s inside functions that contain at least one condition guard. */
pragma[nomagic]
Call callInGuardedFunction(Function f, int callLine) {
  exists(IfStmt ifst |
    conditionGuardIfStmt(_, ifst, _) and
    f = ifst.getEnclosingFunction()
  ) and
  result.getEnclosingFunction() = f and
  callLine = result.getLocation().getStartLine()
}

/**
 * Holds if `ic` at `ifst` guards `Call` `call`.
 */
pragma[nomagic]
predicate conditionGuardsCall(
  InterestingConditionCalls ic, IfStmt ifst, Call call
) {
  exists(int minLine, int maxLine, int callLine |
    conditionGuardSpan(ic, ifst, minLine, maxLine) and
    call = callInGuardedFunction(ifst.getEnclosingFunction(), callLine) and
    call != ic and
    not ifst.getCondition().getAChild*() = call and
    not (
      conditionGuardIfStmt(ic, ifst, true) and
      thenBranchHasAbort(ifst) and
      ifst.getThen().getAChild*() = call
    ) and
    callLine >= minLine and
    callLine <= maxLine
  )
}

/** Resolves an initializer expression to a target Function. */
predicate resolvesToFunction(Expr expr, Function target) {
  target = expr.(FunctionAccess).getTarget()
  or
  resolvesToFunction(expr.(Conversion).getExpr(), target)
  or
  resolvesToFunction(expr.(ParenthesisExpr).getExpr(), target)
}

/**
 * Holds if `cal` is a `genl_ops`, `genl_small_ops`, or `genl_split_ops`
 * initializer registering `handler` with `flagsVal`.
 */
pragma[nomagic]
predicate genlOpsEntry(
  ClassAggregateLiteral cal, Function handler, Expr flagsExpr, int flagsVal
) {
  exists(Struct s, Field callbackField, ClassAggregateLiteral subCal |
    cal.getType().getUnspecifiedType() = s and
    s.getName() in ["genl_ops", "genl_small_ops", "genl_split_ops"] and
    callbackField.getName() in [
        "doit", "dumpit", "start", "done", "pre_doit", "post_doit"
      ] and
    subCal = cal.getAChild*() and
    resolvesToFunction(subCal.getAFieldExpr(callbackField), handler) and
    (
      exists(Field flagsField |
        flagsField.getName() = "flags" and
        flagsExpr = cal.getAFieldExpr(flagsField) and
        flagsVal = flagsExpr.getValue().toInt()
      )
      or
      not exists(Field flagsField |
        flagsField.getName() = "flags" and
        exists(cal.getAFieldExpr(flagsField))
      ) and
      flagsExpr = cal and
      flagsVal = 0
    )
  )
}

/**
 * Holds if `handler` is declaratively gated by `GENL_ADMIN_PERM` ("capable")
 * or `GENL_UNS_ADMIN_PERM` ("ns_capable") across all its Generic Netlink registrations.
 */
pragma[nomagic]
predicate genlDeclarativeGateFunction(
  Function handler, string gateType, string nsTag, Expr flagsExpr,
  ClassAggregateLiteral cal
) {
  exists(int flagsVal |
    genlOpsEntry(cal, handler, flagsExpr, flagsVal) and
    exists(handler.getBlock()) and
    (
      flagsVal.bitAnd(1) != 0 and
      gateType = "capable" and
      nsTag = "init_user_ns" and
      not exists(int otherFlags |
        genlOpsEntry(_, handler, _, otherFlags) and
        otherFlags.bitAnd(1) = 0
      )
      or
      flagsVal.bitAnd(16) != 0 and
      gateType = "ns_capable" and
      nsTag = "net_ns" and
      not exists(int otherFlags |
        genlOpsEntry(_, handler, _, otherFlags) and
        otherFlags.bitAnd(17) = 0
      )
    )
  )
}

/**
 * Emits declarative Generic Netlink gate rows for `condition-graph-direct.ql`.
 */
pragma[nomagic]
predicate genlDeclarativeGate(
  string gateType, string defLoc, string condLoc, string arg, string callStr,
  string callLoc
) {
  exists(
    ClassAggregateLiteral cal, Function handler, Expr flagsExpr, string nsTag
  |
    genlDeclarativeGateFunction(handler, gateType, nsTag, flagsExpr, cal) and
    defLoc = flagsExpr.getLocation().toString() and
    condLoc = cal.getLocation().toString() and
    arg = "CAP_NET_ADMIN" and
    callStr = "__genl_ops_gate__:" + nsTag and
    callLoc =
      "file://" + handler.getFile().toString() + ":" +
        handler.getBlock().getLocation().getStartLine().toString() + ":1:" +
        handler.getBlock().getLocation().getEndLine().toString() + ":1"
  )
}

/**
 * Unified row relation for `condition-graph-direct.ql` (`conditions` SQLite table).
 *
 * Polymorphic `callStr` (`conditions.call`) / `callLoc` (`conditions.call_loc`) contract:
 * 1. Direct call rows: `callStr` is `call.toString()` (e.g., `"call to foo"` or
 *    `"call to expression"`), and `callLoc` is the call expression location.
 * 2. Synthetic guarded-span rows: `callStr` is `"__guarded_span__:<ns_scope>"`,
 *    and `callLoc` encodes the controlled line interval `[minLine, maxLine]` as
 *    `"file://<path>:<minLine>:1:<maxLine>:1"`.
 * 3. Synthetic Generic Netlink declarative gate rows: `callStr` is
 *    `"__genl_ops_gate__:<ns_scope>"`, and `callLoc` encodes the gated handler's
 *    body line span `[startLine, endLine]` as
 *    `"file://<path>:<startLine>:1:<endLine>:1"`.
 */
predicate conditionDirectRow(
  string gateType, string defLoc, string condLoc, string arg, string callStr,
  string callLoc
) {
  exists(InterestingConditionCalls ic, IfStmt condition, Call call |
    conditionGuardsCall(ic, condition, call) and
    gateType = ic.getInterestingType() and
    defLoc = ic.getInterestingLocationString() and
    condLoc = condition.getLocation().toString() and
    arg = ic.getInterestingArgString() and
    callStr = call.toString() and
    callLoc = call.getLocation().toString()
  )
  or
  exists(
    CapabilityConditionCall cap, IfStmt condition, int minLine, int maxLine
  |
    conditionGuardSpan(cap, condition, minLine, maxLine) and
    gateType = cap.getInterestingType() and
    defLoc = cap.getInterestingLocationString() and
    condLoc = condition.getLocation().toString() and
    arg = cap.getInterestingArgString() and
    callStr = "__guarded_span__:" + cap.getNsScope() and
    callLoc =
      "file://" + condition.getFile().toString() + ":" + minLine.toString() +
        ":1:" + maxLine.toString() + ":1"
  )
  or
  genlDeclarativeGate(gateType, defLoc, condLoc, arg, callStr, callLoc)
}
