/**
 * @name SQLI Vulnerability
 * @description Using untrusted strings in a sql query allows sql injection attacks.
 * @kind
 * @id python/SQLIVulnerableModule
 * @problem.severity warning
 */

// See 
// https://codeql.github.com/docs/codeql-language-guides/analyzing-data-flow-in-python/#using-global-data-flow
// for templates and more information.
//
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

from DataFlow::Node source, DataFlow::Node sink
where SqliFlow::flow(source, sink)
select sink, source, sink, "Possible SQL injection"
