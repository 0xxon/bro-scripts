# @TEST-EXEC: bro -C -r $TRACES/tls/missing-intermediate.pcap %INPUT
# @TEST-EXEC: btest-diff ssl.log

@load ../../../validate-certs-cache-intermediates.bro
