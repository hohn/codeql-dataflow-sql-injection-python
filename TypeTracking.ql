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
DataFlow::TypeTrackingNode firebase(DataFlow::TypeTracker t) {
  t.start() and
  result = API::moduleImport("sqlite3").getAValueReachableFromSource()
  or
  exists(DataFlow::TypeTracker t2 | result = firebase(t2).track(t2, t))
}

DataFlow::LocalSourceNode firebase() { result = firebase(DataFlow::TypeTracker::end()) }

DataFlow::TypeTrackingNode firebaseConnect(DataFlow::TypeTracker t) {
  t.start() and
  result = firebase().getAMethodCall("connect")
  or
  exists(DataFlow::TypeTracker t2 | result = firebase(t2).track(t2, t))
}

DataFlow::LocalSourceNode firebaseConnect() { 
  result = firebaseConnect(DataFlow::TypeTracker::end()) }

// DataFlowPublic.MethodCallNode
import semmle.python.dataflow.new.internal.DataFlowPublic

MethodCallNode firebaseCloseCall() { result = firebaseConnect().getAMethodCall("close") }

select firebaseCloseCall()


// XX:
// https://codeql.github.com/docs/codeql-language-guides/using-type-tracking-for-api-modeling/#tracking-associated-data
//
