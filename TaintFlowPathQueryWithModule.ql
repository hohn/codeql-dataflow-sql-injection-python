/**
 * @name SQLI Vulnerability
 * @description Using untrusted strings in an SQL query allows SQL injection attacks.
 * @kind path-problem
 * @id python/SQLIVulnerableModule
 * @problem.severity warning
 */

import python
import semmle.python.ApiGraphs
import semmle.python.dataflow.new.TaintTracking
import semmle.python.Concepts

/**
 * A flow-state representing whether user input has been sanitized.
 */
newtype TInputSanitizationState =
  TInputUnsanitizedState() or
  TInputSanitizedState(Call sanitizeCall)

/**
 * A class describing the
 */
class InputSanitizationState extends TInputSanitizationState {
  string toString() {
    this = TInputUnsanitizedState() and result = "unsanitized"
    or
    this = TInputSanitizedState(_) and result = "sanitized"
  }
}

/**
 * A flow-state in which user input has *not* been sanitized.
 */
class InputUnsanitizedState extends InputSanitizationState, TInputUnsanitizedState { }

/**
 * A flow-state in which the type of a dynamic input array has been validated.
 */
class InputSanitizedState extends InputSanitizationState, TInputSanitizedState {
  Call call;
  DataFlow::Node node1;
  DataFlow::Node node2;

  InputSanitizedState() {
    this = TInputSanitizedState(call) and
    node1.asExpr() = call.getArg(0) and
    node2.asExpr() = call and
    call.getFunc().(Name).getId() = "sanitize"
  }

  /**
   * Returns the call to a function that sanitizes the user input.
   */
  Call getCall() { result = call }

  /**
   * Returns the node *from* which the state-changing step occurs
   */
  DataFlow::Node getFstNode() { result = node1 }

  /**
   * Returns the node *to* which the state-changing step occurs
   */
  DataFlow::Node getSndNode() { result = node2 }
}

API::CallNode getAnExecuteScriptCall() {
  result =
    any(API::moduleImport("sqlite3"))
        .getMember("connect")
        .getReturn()
        .getMember("executescript")
        .getACall()
}

module SqliFlowConfig implements DataFlow::StateConfigSig {
  class FlowState = TInputSanitizationState;

  predicate isSource(DataFlow::Node source, FlowState state) {
    API::moduleImport("builtins").getMember("input").getACall() = source and
    state instanceof InputUnsanitizedState
  }

  predicate isSink(DataFlow::Node sink, FlowState state) {
    getAnExecuteScriptCall().getArg(0) = sink and
    state instanceof InputSanitizationState // ignore
  }

  predicate isAdditionalFlowStep(DataFlow::Node node1, DataFlow::Node node2) {
    exists(RegexExecution re | node1 = re.getString() and node2 = re)
  }

  predicate isAdditionalFlowStep(
    DataFlow::Node node1, FlowState state1, DataFlow::Node node2, FlowState state2
  ) {
    state1 instanceof InputUnsanitizedState and
    node1 = state2.(InputSanitizedState).getFstNode() and
    node2 = state2.(InputSanitizedState).getSndNode()
  }

  predicate isBarrier(DataFlow::Node node, FlowState state) {
    state instanceof InputUnsanitizedState and
    exists(InputSanitizedState iss | iss.getSndNode() = node)
  }
}

module SqliFlow = TaintTracking::GlobalWithState<SqliFlowConfig>;

import SqliFlow::PathGraph

from SqliFlow::PathNode source, SqliFlow::PathNode sink, string message
where
  SqliFlow::flowPath(source, sink) and
  (
    sink.getState() instanceof InputSanitizedState and
    message = "Possible SQL injection, but user input might be sanitized."
    or
    sink.getState() instanceof InputUnsanitizedState and
    message = "Possible SQL injection."
  )
select sink, source, sink, message
