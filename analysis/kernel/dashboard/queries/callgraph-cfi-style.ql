/**
 * @name all-calls
 * @id callgraph-all
 * @kind path-problem
 * @severity warning
 */

 import cpp
 import semmle.code.cpp.pointsto.CallGraph
 import semmle.code.cpp.ir.dataflow.ResolveCall
 
 cached predicate exprCallEdge(ExprCall a, Function b) {
    a.getExpr().(TargetPointsToExpr).pointsTo() = b and
    a.getExpr().(TargetPointsToExpr).confidence() >= 0.1 and
    exists(Struct s, Field f | s.getAField() = f and f.getAnAccess() = a.getExpr() and f.getAnAssignedValue() = b.getAnAccess()) and
    //a.getExpr().getType() = b.getType() and
   // Get the number of parameters of the function
   exists(int numParams |
     numParams = count(b.getParameter(_)) and
     // Iterate over each parameter
     forall(int i | i in [0 .. numParams - 1] |
       exists(Parameter p | p = b.getParameter(i) |
         // Get the type of the parameter
         exists(Type paramType | paramType = p.getType() |
           // Get the argument at the corresponding index
           exists(Expr arg | arg = a.getArgument(i) |
             // Check if the argument's type is compatible with the parameter's type
             arg.getType().(PointerType).getBaseType() = paramType
             or
             arg.getType() = paramType
           )
         )
       )
     )
   )
 }
 
 predicate notInteresting(Function fun) {
   //fun.isCompilerGenerated() or
   fun.getName().matches("__compiletime_assert_%") or
   //exists(Function overload | overload = fun.getAnOverload()) or
   fun.getBlock().isEmpty() 
   //fun.getAnAttribute().hasName("weak") 
 }
 
 query predicate edges(ControlFlowNode a, ControlFlowNode b) {
   // ExprCall to Function
   exprCallEdge(a, b)
   or
   a = b.(Call).getEnclosingFunction()
   or
   b = resolveCall(a)
 }
 
 from ControlFlowNode nodeFrom, ControlFlowNode nodeTo
 where edges(nodeFrom, nodeTo)
 //and  not edges(_, nodeFrom) and
 //nodeTo.(FunctionCall).getTarget().getName() = "kzalloc"
 select nodeTo, nodeFrom, nodeTo, "callgraph-all"
 