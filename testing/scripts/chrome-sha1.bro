# @TEST-EXEC: bro -C -r $TRACES/tls/http-ocsp-reddit.pcap %INPUT
# @TEST-EXEC: bash -c "if [ -f notice.log ]; then false; else true; fi"
# @TEST-EXEC: bro -C -r $TRACES/tls/0xxon.pcap %INPUT
# @TEST-EXEC: bash -c "if [ -f notice.log ]; then false; else true; fi"
# @TEST-EXEC: bro -C -r $TRACES/tls/abo.heise.de-new.pcap %INPUT
# @TEST-EXEC: bash -c "if [ -f notice.log ]; then false; else true; fi"
# @TEST-EXEC: bro -C -r $TRACES/tls/abo.heise.de.pcap %INPUT
# @TEST-EXEC: btest-diff notice.log

@load ../../../chrome-sha1.bro

redef Site::local_nets += { 0.0.0.0/0 };
