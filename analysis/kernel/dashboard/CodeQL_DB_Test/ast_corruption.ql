/**
 * @name Intra-Procedural AST & CFG Corruption (ErrorExpr Black Holes)
 * @description Detects unparseable C/GNU expressions replaced by CodeQL's EDG frontend
 *              with ErrorExpr AST black holes inside function bodies, branch conditions,
 *              and call arguments.
 * @kind table
 * @id cpp/kernel-db-test/ast-corruption
 */

import cpp

from
  int totalErrorExprs,
  int totalDefinedFunctions,
  int corruptedFunctions,
  int conditionErrorExprs,
  int callArgErrorExprs,
  int returnErrorExprs
where
  totalErrorExprs = count(ErrorExpr e) and
  totalDefinedFunctions = count(Function fn | fn.hasDefinition() and exists(fn.getBlock())) and
  corruptedFunctions = count(Function fn |
    fn.hasDefinition() and exists(ErrorExpr e | e.getEnclosingFunction() = fn)
  ) and
  conditionErrorExprs = count(ErrorExpr e |
    exists(IfStmt i | i.getCondition().getAChild*() = e) or
    exists(Loop l | l.getCondition().getAChild*() = e) or
    exists(ConditionalExpr c | c.getCondition().getAChild*() = e)
  ) and
  callArgErrorExprs = count(ErrorExpr e |
    exists(Call c | c.getAnArgument().getAChild*() = e or c.getAChild() = e)
  ) and
  returnErrorExprs = count(ErrorExpr e |
    exists(ReturnStmt r | r.getExpr().getAChild*() = e)
  )
select
  totalErrorExprs,
  totalDefinedFunctions,
  corruptedFunctions,
  conditionErrorExprs,
  callArgErrorExprs,
  returnErrorExprs
