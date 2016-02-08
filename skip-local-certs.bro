redef Site::local_nets += { };

redef record X509::Info += {
	local_cert: bool &default=F;
};

event file_state_remove(f: fa_file) &priority=6
	{
	if ( ! f$info?$x509 )
		return;

	for ( i in f$info$tx_hosts )
		{
		if ( Site::is_local_addr(i) )
			f$info$x509$local_cert = T;
		}
	}

function no_local_certs(rec: X509::Info): bool
  {
  return ! rec$local_cert;
  }

event bro_init () &priority=-5
	{
	local f = Log::get_filter(X509::LOG, "default");
	Log::remove_filter(X509::LOG, "default");
	f$pred=no_local_certs;
	Log::add_filter(X509::LOG, f);
	}

