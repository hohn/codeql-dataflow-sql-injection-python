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

// Test
// from Call c
// where isSink(c, _)
// select c
// ----------------------------------------
// Some illustration of
// https://codeql.github.com/docs/codeql-language-guides/analyzing-data-flow-in-python/#using-local-data-flow
//
// You can map between data flow nodes and expressions/control-flow nodes using the member predicates asExpr and asCfgNode.
//
// Local flow into the Call
// from Call c, DataFlow::Node source
// where isSink(c, _) and
//     DataFlow::localFlow(source, DataFlow::exprNode(c))
// select source, c
//
// Local flow to the call's argument
// from Call c, DataFlow::Node source, DataFlow::Node arg0
// where isSink(c, arg0) and
//     DataFlow::localFlow(source, arg0)
// select source, arg0
// ----------------------------------------
// Some illustration of
// https://codeql.github.com/docs/codeql-language-guides/analyzing-data-flow-in-python/#using-local-taint-tracking
//
// Find local taint flow involving the call's argument
// conn.executescript(query)
//
// import semmle.python.dataflow.new.TaintTracking
// from Call c, DataFlow::Node source, DataFlow::Node arg0
// where
//   isSink(c, arg0) and
//   TaintTracking::localTaint(source, arg0)
// select source, arg0
//
// ----------------------------------------
// https://codeql.github.com/docs/codeql-language-guides/analyzing-data-flow-in-python/#using-local-sources
//
// Use this project's codeql db for documentation examples:
//
// from DataFlow::CallCfgNode call, DataFlow::ExprNode expr
// where
//   call = API::moduleImport("os").getMember("open").getACall() and
//   DataFlow::localFlow(expr, call.getArg(0))
// select call, expr
//
// To restrict attention to local sources, and to simultaneously make the analysis more performant, we have the QL class LocalSourceNode. We could demand that expr is such a node:
// //
// from DataFlow::CallCfgNode call, DataFlow::ExprNode expr
// where
//   call = API::moduleImport("os").getMember("open").getACall() and
//   DataFlow::localFlow(expr, call.getArg(0)) and
//   expr instanceof DataFlow::LocalSourceNode
// // Check documentation for LocalSourceNode for more details.
// select call, expr

// Enforce this by casting and using the member function flowsTo on LocalSourceNode like so.  This gives a more concise version:
// //
// from DataFlow::CallCfgNode call, DataFlow::ExprNode expr
// where
//   call = API::moduleImport("os").getMember("open").getACall() and
//   expr.(DataFlow::LocalSourceNode).flowsTo(call.getArg(0))
// select call, expr
// //

// This query finds instances where a parameter is used as the name when opening a file:
// //
// from DataFlow::CallCfgNode call, DataFlow::ParameterNode p
// where
//   call = API::moduleImport("os").getMember("open").getACall() and
//   DataFlow::localFlow(p, call.getArg(0))
// select p, call
// //

// If we want to know if the parameter influences the file name, we can use taint tracking instead of data flow. This query finds calls to os.open where the filename is derived from a parameter:
//
import semmle.python.dataflow.new.TaintTracking
from DataFlow::CallCfgNode call, DataFlow::ParameterNode p
where
  call = API::moduleImport("os").getMember("open").getACall() and
  TaintTracking::localTaint(p, call.getArg(0))
select p, call
//
// ----------------------------------------
// 