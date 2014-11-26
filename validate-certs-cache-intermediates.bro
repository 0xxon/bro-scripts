##! Perform full certificate chain validation for SSL certificates.
# Also caches all intermediate certificates encountered so far and use them
# for future validations.

@load base/frameworks/notice
@load base/protocols/ssl

module SSL;

export {
	redef enum Notice::Type += {
		## This notice indicates that the result of validating the
		## certificate along with its full certificate chain was
		## invalid.
		Invalid_Server_Cert
	};

	redef record Info += {
		## Result of certificate validation for this connection.
		validation_status: string &log &optional;
	};

	## MD5 hash values for recently validated chains along with the
	## validation status are kept in this table to avoid constant
	## validation every time the same certificate chain is seen.
	global recently_validated_certs: table[string] of X509::Result = table()
		&read_expire=5mins &synchronized &redef;
}

global intermediate_cache: table[string] of vector of opaque of x509 &synchronized;

function cache_validate(chain: vector of opaque of x509): X509::Result
	{
	local chain_hash: vector of string = vector();

	for ( i in chain )
		chain_hash[i] = sha1_hash(x509_get_certificate_string(chain[i]));

	local chain_id = join_string_vec(chain_hash, ".");

	# If we tried this certificate recently, just return the cached result.
	if ( chain_id in recently_validated_certs )
		return recently_validated_certs[chain_id];

	local result = x509_verify(chain, root_certs);
	recently_validated_certs[chain_id] = result;

	# if we have a working chain where we did not store the intermediate certs
	# in our cache yet - do so
	local result_chain = result$chain_certs;
	if ( result$result_string == "ok" && |result_chain| > 2 )
		{
		local icert = x509_parse(result_chain[1]);
		if ( icert$subject !in intermediate_cache )
			{
			local cachechain: vector of opaque of x509;
			for ( i in result_chain )
				{
				if ( i >=1 && i<=|result_chain|-2 )
					cachechain[i-1] = result_chain[i];
				}
			intermediate_cache[icert$subject] = cachechain;
			}
		}

	return result;
	}

event ssl_established(c: connection) &priority=3
	{
	# If there aren't any certs we can't very well do certificate validation.
	if ( ! c$ssl?$cert_chain || |c$ssl$cert_chain| == 0 ||
	     ! c$ssl$cert_chain[0]?$x509 )
		return;

	local intermediate_chain: vector of opaque of x509 = vector();
	local issuer = c$ssl$cert_chain[0]$x509$certificate$issuer;
	local result: X509::Result;

	# look if we already have a working chain for the issuer of this cert.
	# If yes, try this chain first instead of using the chain supplied from
	# the server.
	if ( issuer in intermediate_cache )
		{
		intermediate_chain[0] = c$ssl$cert_chain[0]$x509$handle;
		for ( i in intermediate_cache[issuer] )
			intermediate_chain[i+1] = intermediate_cache[issuer][i];

		result = cache_validate(intermediate_chain);
		if ( result$result_string == "ok" )
			return;
		}

	# validation with known chains failed or there was no fitting intermediate
	# in our store.
	# Fall back to validating the certificate with the server-supplied chain
	local chain: vector of opaque of x509 = vector();
	for ( i in c$ssl$cert_chain )
		{
		if ( c$ssl$cert_chain[i]?$x509 )
			chain[i] = c$ssl$cert_chain[i]$x509$handle;
		}

	result = cache_validate(chain);
	c$ssl$validation_status = result$result_string;

	if ( result$result_string != "ok" )
		{
		local message = fmt("SSL certificate validation failed with (%s)", c$ssl$validation_status);
		NOTICE([$note=Invalid_Server_Cert, $msg=message,
		        $sub=c$ssl$subject, $conn=c,
		        $identifier=cat(c$id$resp_h,c$id$resp_p,c$ssl$validation_status)]);
		}
	}
