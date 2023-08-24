// Documentation for JavaScript, also applicable here:
// https://codeql.github.com/docs/codeql-language-guides/using-type-tracking-for-api-modeling/#using-type-tracking-for-api-modeling
//
// You can track data through an API by creating a model using the CodeQL type-tracking library.
// The type-tracking library makes it possible to track values through properties and function calls
//
import python
import semmle.python.ApiGraphs
import semmle.python.dataflow.new.TypeTracker

//
// See TypeTracker docs for details
//
// Adapted to this repository's Python code.
// Find places where sqlite `Connection`s (from `sqlite3.connect`) ions are closed (via connection.close())
//
DataFlow::TypeTrackingNode sqlite(DataFlow::TypeTracker t) {
  t.start() and
  result = API::moduleImport("sqlite3").getAValueReachableFromSource()
  or
  exists(DataFlow::TypeTracker t2 | result = sqlite(t2).track(t2, t))
}

DataFlow::LocalSourceNode sqlite() { result = sqlite(DataFlow::TypeTracker::end()) }

// --------
DataFlow::TypeTrackingNode sqliteConnect(DataFlow::TypeTracker t) {
  t.start() and
  result = sqlite().getAMethodCall("connect")
  or
  exists(DataFlow::TypeTracker t2 | result = sqliteConnect(t2).track(t2, t))
}

DataFlow::LocalSourceNode sqliteConnect() { result = sqliteConnect(DataFlow::TypeTracker::end()) }

// --------
DataFlow::TypeTrackingNode sqliteClose(DataFlow::TypeTracker t) {
  t.start() and
  result = sqliteConnect().getAMethodCall("close")
  or
  exists(DataFlow::TypeTracker t2 | result = sqliteClose(t2).track(t2, t))
}

DataFlow::LocalSourceNode sqliteClose() { result = sqliteClose(DataFlow::TypeTracker::end()) }

// --------
// DataFlowPublic.MethodCallNode
import semmle.python.dataflow.new.internal.DataFlowPublic

MethodCallNode sqliteCloseCall() { result = sqliteClose() }

select sqliteCloseCall()
//
// When to use type tracking:
//
// https://codeql.github.com/docs/codeql-language-guides/using-type-tracking-for-api-modeling/#when-to-use-type-tracking
