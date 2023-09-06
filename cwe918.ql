/**
 * @name Full server-side request forgery
 * @description Making a network request to a URL that is fully user-controlled allows for request forgery attacks.
 * @ kind path-problem
 * @problem.severity error
 * @security-severity 9.1
 * @precision high
 * @id py/full-ssrf
 * @tags security
 *       external/cwe/cwe-918
 */

import python
import semmle.python.security.dataflow.ServerSideRequestForgeryQuery
import semmle.python.security.dataflow.ServerSideRequestForgeryCustomizations
// import semmle.python.frameworks.Flask
import semmle.python.Frameworks

from
  // FullServerSideRequestForgeryConfiguration fullConfig,
  DataFlow::Node source, DataFlow::Node sink, string srcf, string snkf
// Http::Client::Request request,
//  ServerSideRequestForgery::Sink ssrfsink // does not find request.get
where
  srcf = source.getLocation().getFile().getBaseName() and
  srcf.matches("%cwe%") and
  snkf = sink.getLocation().getFile().getBaseName() and
  snkf.matches("%cwe%") and
  // request = sink.(Sink).getRequest() and
  // fullConfig.hasFlow(source, sink) and
  // fullyControlledRequest(request)
  source != sink
select source, srcf, sink, snkf
// ssrfsink, ssrfsink.getRequest() as request, request.getLocation().getFile().getBaseName()
// request, source, sink, "The full URL of this request depends on a $@.", source,
//   "user-provided value"
//
// from
//   FullServerSideRequestForgeryConfiguration fullConfig, DataFlow::PathNode source,
//   DataFlow::PathNode sink, Http::Client::Request request
// where
//   request = sink.getNode().(Sink).getRequest() and
//   fullConfig.hasFlowPath(source, sink) and
//   fullyControlledRequest(request)
// select request, source, sink, "The full URL of this request depends on a $@.", source.getNode(),
//   "user-provided value"
//
// XX: no longer works on example
