import python
import semmle.python.ApiGraphs



// source
//     info = input().strip()
// 
// from API::Node nd
// where nd = API::moduleImport("builtins")
// select nd, nd.getAMember(), nd.getMember("input")

// select API::moduleImport("builtins").getMember("input")


// sink
//     conn.executescript(query)     # Unsafe, used for illustration
//     ^^^^                      Attribute.getObject()
//          ^^^^^^^^^^^^         Attribute.getName()
//     ^^^^^^^^^^^^^^^^^         Attribute
//                        ^^^^^
//     ^^^^^^^^^^^^^^^^^^^^^^^^^  Call
from Call cl, Attribute at, Expr query
where cl.getAChildNode() = at 
and at.getName() = "executescript"
and at.getLocation().getFile().getBaseName() = "add-user.py"
and query = cl.getPositionalArg(0)
select cl, at.getName(), query


// connect them

