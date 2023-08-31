/**
 * @name Predefined sources and sinks
 * @description https://codeql.github.com/docs/codeql-language-guides/analyzing-data-flow-in-python/#predefined-sources-and-sinks
 * @kind path-problem
 * @id python/predefined-sources-and-sinks
 * @problem.severity warning
 */

//  The class RemoteFlowSource (defined in module semmle.python.dataflow.new.RemoteFlowSources) represents data flow from remote network inputs. This is useful for finding security problems in networked services.
//
//  The library Concepts (defined in module semmle.python.Concepts) contain several subclasses of DataFlow::Node that are security relevant, such as FileSystemAccess and SqlExecution.
//
//  The module Attributes (defined in module semmle.python.dataflow.new.internal.Attributes) defines AttrRead and AttrWrite which handle both ordinary and dynamic attribute access.
// https://codeql.github.com/docs/codeql-language-guides/analyzing-data-flow-in-python/#id2
//
// This query shows a data flow configuration that uses all network input as data sources:
import python
import semmle.python.dataflow.new.DataFlow
import semmle.python.dataflow.new.TaintTracking
import semmle.python.dataflow.new.RemoteFlowSources
import semmle.python.Concepts
import semmle.python.ApiGraphs

//
// Extend FileSystemAccess::Range to include SqlExecution
// XX: This works, but SqlExecution should be extended instead.
//
class SqlAccess extends FileSystemAccess::Range {
  Call call;

  SqlAccess() {
    // Include conn.executescript(query)
    call.getFunc().(Attribute).getName() = "executescript" and
    this.asExpr() = call.getArg(0)
    // This is result 413 of 526; narrow things down further
  }

  override DataFlow::Node getAPathArgument() { result = this }
}

//
// Include input()(?.strip()?) as RemoteFlowSource
//
class TerminalInput extends RemoteFlowSource::Range {
  TerminalInput() {
    // Include input().strip()
    API::moduleImport("builtins").getMember("input").getACall() = this
  }

  override string getSourceType() { result = "terminal input" }
}

module RemoteToFileConfiguration implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) { source instanceof RemoteFlowSource }

  predicate isSink(DataFlow::Node sink) {
    sink = any(FileSystemAccess fa).getAPathArgument() and
    // kludge
    sink.asCfgNode().getNode().toString() = "query"
  }
}

module RemoteToFileFlow = TaintTracking::Global<RemoteToFileConfiguration>;

import RemoteToFileFlow::PathGraph

from RemoteToFileFlow::PathNode input, RemoteToFileFlow::PathNode fileAccess
where RemoteToFileFlow::flowPath(input, fileAccess)
select fileAccess, input, fileAccess, "This db write uses data from $@.", input, "user-controllable input."
