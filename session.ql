import python
import semmle.python.ApiGraphs

// source
//     info = input().strip()
//
// from API::Node nd1
// where nd1 = API::moduleImport("builtins").getMember("input")
// select nd1

// select API::moduleImport("builtins").getMember("input")
class MySource extends API::Node {
  MySource() { this = API::moduleImport("builtins").getMember("input") }

  override string toString() { result = this.toString() }
}
from MySource src 
select src

// sink
//     conn.executescript(query)     # Unsafe, used for illustration
//     ^^^^                      Attribute.getObject()
//          ^^^^^^^^^^^^         Attribute.getName()
//     ^^^^^^^^^^^^^^^^^         Attribute
//                        ^^^^^
//     ^^^^^^^^^^^^^^^^^^^^^^^^^  Call
// from Call cl, Attribute at, Expr query
// where cl.getAChildNode() = at
// and at.getName() = "executescript"
// and at.getLocation().getFile().getBaseName() = "add-user.py"
// and query = cl.getPositionalArg(0)
// select cl, at.getName(), query
class MySink extends Expr {
  Call cl;
  Attribute at;

  MySink() {
    cl.getAChildNode() = at and
    at.getName() = "executescript" and
    at.getLocation().getFile().getBaseName() = "add-user.py" and
    this = cl.getPositionalArg(0)
  }
}
// from MySink ms
// select ms


// connect them
