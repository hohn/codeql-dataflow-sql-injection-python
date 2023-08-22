// https://codeql.github.com/docs/codeql-language-guides/using-api-graphs-in-python/
//
// API graphs are a uniform interface for referring to functions, classes, and methods defined in external libraries.
//
import python
import semmle.python.ApiGraphs

//
// // one result, no location
// select API::moduleImport("re")
//
// // Select all references to the re module in the current database, accounting for local flow.
// select API::moduleImport("re").getAValueReachableFromSource()
//
// // Select all references to the `logging` module in our toy problem.
// from DataFlow::Node dflog
// where API::moduleImport("logging").getAValueReachableFromSource() = dflog
// and dflog.asExpr().getLocation().getFile().getShortName() = "add-user.py"
// select dflog
//
// ----
// https://codeql.github.com/docs/codeql-language-guides/using-api-graphs-in-python/#accessing-attributes
//
// // Find logging.info
// //
// select API::moduleImport("logging").getMember("info").getAValueReachableFromSource()
//
// ----
// https://codeql.github.com/docs/codeql-language-guides/using-api-graphs-in-python/#calls-and-class-instantiations
//
// 1. To track instances of classes defined in external libraries
// or
// 2. the results of calling externally defined functions, you can use the getReturn method.
//
// // 1: argparse.ArgumentParser()
// select API::moduleImport("argparse").getMember("ArgumentParser").getReturn().asSource()
//
// // 2: logging.info()
// select API::moduleImport("logging").getMember("info").getReturn().getAValueReachableFromSource()
//
// ----
// https://codeql.github.com/docs/codeql-language-guides/using-api-graphs-in-python/#built-in-functions-and-classes
//
select API::builtin("input").getACall()
