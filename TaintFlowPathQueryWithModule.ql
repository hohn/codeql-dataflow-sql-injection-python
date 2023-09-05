/**
 * @name SQLI Vulnerability
 * @description Using untrusted strings in a sql query allows sql injection attacks.
 * @kind path-problem
 * @id python/SQLIVulnerableModule
 * @problem.severity warning
 */

// See
// https://codeql.github.com/docs/writing-codeql-queries/creating-path-queries/#constructing-a-path-query
// for a summary of the modifications needed to make a path query out of a query.
// Or see the diff below.
//
// Path queries have more features than shown here; see
// https://codeql.github.com/docs/writing-codeql-queries/creating-path-queries/#generating-path-explanations
// for more information.

import python
import semmle.python.dataflow.new.DataFlow
import semmle.python.ApiGraphs
import semmle.python.dataflow.new.TaintTracking

module SqliFlowConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    API::moduleImport("builtins").getMember("input").getACall() = source
  }

  predicate isSink(DataFlow::Node sink) {
    exists(Call call |
      call.getFunc().(Attribute).getName() = "executescript" and
      sink.asExpr() = call.getArg(0)
    )
  }
}

module SqliFlow = TaintTracking::Global<SqliFlowConfig>;

import SqliFlow::PathGraph

from SqliFlow::PathNode source, SqliFlow::PathNode sink
where SqliFlow::flowPath(source, sink)
select sink, source, sink, "Possible SQL injection"

// The diff from the plain query is:
// from DataFlow::Node source, DataFlow::Node sink
// < where SqliFlow::flow(source, sink)
// ---
// > import SqliFlow::PathGraph
// > 
// > from SqliFlow::PathNode source, SqliFlow::PathNode sink
// > where SqliFlow::flowPath(source, sink)
