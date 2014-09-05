This repository contains a number of small Bro scripts that could be useful.

[counttable.bro](counttable.bro)
--------------------------------

This script provives a COUNTTABLE type for the summary statistics framework. This type is basically like
SUM, with the difference that you have to provide a $str in the observation, and
the SUM is calculated independently for each $str.

This makes it optimal to sum up small number of keys per host like, for example,
all the TLS ciphers you saw in use for hosts on the local host.

Do not try to use this with a big number of different $str values, especially
in a cluster setup. It will probably lead to excessive resource use.

[ssl-ciphers.bro](ssl-ciphers.bro)
----------------------------------

This script calculates the percentage of the use of the different TLS cipher suites for each host in the local network.
