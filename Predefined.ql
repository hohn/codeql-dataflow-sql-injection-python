/**
 * @name Predefined sources and sinks
 * @description https://codeql.github.com/docs/codeql-language-guides/analyzing-data-flow-in-python/#predefined-sources-and-sinks
 * @kind
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

module RemoteToFileConfiguration implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    source instanceof RemoteFlowSource
  }

  predicate isSink(DataFlow::Node sink) {
    sink = any(FileSystemAccess fa).getAPathArgument()
  }
}

module RemoteToFileFlow = TaintTracking::Global<RemoteToFileConfiguration>;

from DataFlow::Node input, DataFlow::Node fileAccess
where RemoteToFileFlow::flow(input, fileAccess)
select fileAccess, "This file access uses data from $@.",
  input, "user-controllable input."