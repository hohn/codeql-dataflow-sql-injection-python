// Documentation for JavaScript, also applicable here:
// https://codeql.github.com/docs/codeql-language-guides/using-type-tracking-for-api-modeling/#using-type-tracking-for-api-modeling
//
// The type-tracking library makes it possible to track values through properties and function calls.  Here, we also track some associated data.
// See https://codeql.github.com/docs/codeql-language-guides/using-type-tracking-for-api-modeling/#tracking-associated-data
//
// The summary with templates: https://codeql.github.com/docs/codeql-language-guides/using-type-tracking-for-api-modeling/#summary
//
import python
import semmle.python.ApiGraphs
import semmle.python.dataflow.new.TypeTracker
// Find places where sqlite `Connection`s (from `sqlite3.connect`) ions are closed (via connection.close())
//
// Note that evaluation is bottom-up so the pathlen formation is subtractive.
//
// --------
import semmle.python.SSA

DataFlow::TypeTrackingNode sqlite(int pathlen, DataFlow::TypeTracker t) {
  t.start() and
  (
    result = API::moduleImport("sqlite3").getAValueReachableFromSource() and
    pathlen = 111
  )
  or
  exists(DataFlow::TypeTracker t2 |
    result = sqlite(pathlen + 1, t2).track(t2, t) and
    // Remove some duplicate intermediates
    not result instanceof ModuleVariableNode and
    not result.asVar() instanceof GlobalSsaVariable
  )
}

DataFlow::LocalSourceNode sqlite(int pathlen) {
  result = sqlite(pathlen, DataFlow::TypeTracker::end())
}

// --------
DataFlow::TypeTrackingNode sqliteConnect(int pathlen, DataFlow::TypeTracker t) {
  t.start() and
  result = sqlite(pathlen + 1).getAMethodCall("connect")
  or
  exists(DataFlow::TypeTracker t2 | result = sqliteConnect(pathlen + 1, t2).track(t2, t))
}

DataFlow::LocalSourceNode sqliteConnect(int pathlen) {
  result = sqliteConnect(pathlen, DataFlow::TypeTracker::end())
}

// --------
DataFlow::TypeTrackingNode sqliteClose(int pathlen, DataFlow::TypeTracker t) {
  t.start() and
  result = sqliteConnect(pathlen + 1).getAMethodCall("close")
  or
  exists(DataFlow::TypeTracker t2 | result = sqliteClose(pathlen + 1, t2).track(t2, t))
}

DataFlow::LocalSourceNode sqliteClose(int pathlen) {
  result = sqliteClose(pathlen, DataFlow::TypeTracker::end())
}

// --------
// DataFlowPublic.MethodCallNode
import semmle.python.dataflow.new.internal.DataFlowPublic

MethodCallNode sqliteCloseCall(int pathlen) { result = sqliteClose(pathlen + 1) }

from int pathlen, MethodCallNode call
where call = sqliteCloseCall(pathlen)
select call, 111-pathlen as jumps, concat(int i | i = [1 .. 111-pathlen] | ".")
