# This script identifies certificates on the local network which will be
# impacted by the Chrome SHA-1 sunset changes. For more details, please
# see http://googleonlinesecurity.blogspot.com/2014/09/gradually-sunsetting-sha-1.html

@load base/protocols/ssl
@load base/frameworks/notice

module ChromeSHA;

export {
	redef enum Notice::Type += {
		## Indicates that the certificate of a host will be impacted by the google
		## SHA-1 sunset changes.
		SSL_Chrome_SHA_Sunset
	};
}

global recently_checked_certs: set[string] = set();

event ssl_established(c: connection)
	{
	if (!Site::is_local_addr(c$id$resp_h))
		return;

	# If there aren't any certs we can't validate the chain.
	if ( ! c$ssl?$cert_chain || |c$ssl$cert_chain| == 0 ||
	     ! c$ssl$cert_chain[0]?$x509 )
		return;

	local chain_id = "";
	local chain: vector of opaque of x509 = vector();

	for ( i in c$ssl$cert_chain )
		{
		chain_id = cat(chain_id, c$ssl$cert_chain[i]$sha1);
		if ( c$ssl$cert_chain[i]?$x509 )
			chain[i] = c$ssl$cert_chain[i]$x509$handle;
		}

	if ( chain_id in recently_checked_certs )
		return;

	add recently_checked_certs[chain_id];

	# This only applies to certificates with an expiry after 2016-01-01.
	local cutoff: time = double_to_time(1451606400.0);

	if ( c$ssl$cert_chain[0]$x509$certificate$not_valid_after < cutoff )
		return;

	local result = x509_verify(chain, SSL::root_certs);

	# If we cannot validate, we cannot tell anything in any case...
	if ( result$result_string != "ok" )
		return;

	local vchain = result$chain_certs;
	for ( i in vchain )
		{
		local cert = x509_parse(vchain[i]);
		if ( cert$subject == cert$issuer )
			# skip the root
			return;

		if ( /^sha1With/ in cert$sig_alg )
			NOTICE([$note=SSL_Chrome_SHA_Sunset,
				$msg=fmt("A certificate in the chain uses SHA-1 as the hash algorithm. Chrome will consider this unsafe in the future"),
				$sub=fmt("Subject: %s, Issuer: %s, Signature algorithm: %s", cert$subject, cert$issuer, cert$sig_alg),
				$conn=c,
				$identifier=cat(c$id$resp_h),
				$suppress_for=7 days
			]);
		}

	}
