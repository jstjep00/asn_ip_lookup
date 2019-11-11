# asn_ip_lookup

This shell script is used to extract IP ranges allocated to Autonomous Systems (AS) using whois and regex. Simply calling the script with number of AS as one of it's arguments prefixed with "AS" looks up the IP ranges under it.

Example:

```
	./asn_ip_lookup.sh AS1234
```

There is also an option to look up multiple AS-s by simply adding more AS numbers one after another. When they're called this way then IP ranges aren't distincted between ASs but simply written down one after another in their own new lines.

Example:

```
	./asn_ip_lookup.sh AS1234 AS5678
```

### To be added soon:
	- Add getopt for command line options like input/output txt lists
	- Add limitation to AS ranges that can be called (according to the RFC, even though their results by whois will be null)
	- Add reverse IP to ASN lookup with whois origin
