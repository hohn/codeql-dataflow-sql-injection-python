import python
import semmle.python.dataflow.new.DataFlow
import semmle.python.ApiGraphs

/*
 * We need an ASTNode as starting point for experiments.
 */

predicate isSink(Call call, DataFlow::Node arg0) {
  call.getFunc().(Attribute).getName() = "executescript" and
  arg0.asExpr() = call.getArg(0)
}

// An illustration of
// https://codeql.github.com/docs/codeql-language-guides/analyzing-data-flow-in-python/#using-local-data-flow
//
// You can map between data flow nodes and expressions/control-flow nodes using the member predicates asExpr and asCfgNode.
//
// ----------------------------------------
// Local flow into the Call
// from Call c, DataFlow::Node source
// where isSink(c, _) and
//     DataFlow::localFlow(source, DataFlow::exprNode(c))
// select source, c
//
// ----------------------------------------
// Local flow to the call's argument
from Call c, DataFlow::Node source, DataFlow::Node arg0
where
  isSink(c, arg0) and
  DataFlow::localFlow(source, arg0)
select source, arg0
