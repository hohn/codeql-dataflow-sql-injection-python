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
from Call cl, Attribute at 
where cl.getAChildNode() = at
select cl, at.getName()

// connect them

