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
// https://codeql.github.com/docs/codeql-language-guides/analyzing-data-flow-in-python/#using-local-taint-tracking
//
// Find local taint flow involving the call's argument,
// conn.executescript(query)
//
import semmle.python.dataflow.new.TaintTracking

from Call c, DataFlow::Node source, DataFlow::Node arg0
where
  isSink(c, arg0) and
  TaintTracking::localTaint(source, arg0)
select source, arg0
