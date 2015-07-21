# Short, simple script that adds the name of the node that processed
# a connection to conn.log.

@load base/frameworks/cluster

@if ( Cluster::is_enabled() )

@load base/protocols/conn

redef record Conn::Info += {
	node: string &optional &log;
};

event connection_state_remove(c: connection)
	{
	c$conn$node = Cluster::node;
	}

@endif
