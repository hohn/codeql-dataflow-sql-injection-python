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

// Use this project's codeql db for documentation examples from
// https://codeql.github.com/docs/codeql-language-guides/analyzing-data-flow-in-python/#using-local-sources
//
// These find results in the Python standard library, not in this repository's source.
//
// from DataFlow::CallCfgNode call, DataFlow::ExprNode expr
// where
//   call = API::moduleImport("os").getMember("open").getACall() and
//   DataFlow::localFlow(expr, call.getArg(0))
// select call, expr
//
// To restrict attention to local sources, and to simultaneously make the analysis
// more performant, we have the QL class LocalSourceNode. We could demand that
// expr is such a node: 
// //
// from DataFlow::CallCfgNode call, DataFlow::ExprNode expr
// where
//   call = API::moduleImport("os").getMember("open").getACall() and
//   DataFlow::localFlow(expr, call.getArg(0)) and
//   expr instanceof DataFlow::LocalSourceNode
//   // Check documentation for LocalSourceNode for more details.
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

// If we want to know if the parameter influences the file name, we can use taint
// tracking instead of data flow. This query finds calls to os.open where the
// filename is derived from a parameter.
//
import semmle.python.dataflow.new.TaintTracking
from DataFlow::CallCfgNode call, DataFlow::ParameterNode p
where
  call = API::moduleImport("os").getMember("open").getACall() and
  TaintTracking::localTaint(p, call.getArg(0))
select p, call

