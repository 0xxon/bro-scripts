# This script adds the length of the discrete log group size of
# the server DH parameters to ssl.log
#
# Questions -> johanna@icir.org

@load base/protocols/ssl

module SSL;

export {
	redef record Info += {
		## DH log group size
		dh_param_size: count &log &optional;
	};
}

event ssl_dh_server_params(c: connection, p: string, q: string, Ys: string) &priority = 5
	{
	set_session(c);

	c$ssl$dh_param_size = |p| * 8; # length of the used prime number in bits
	}
