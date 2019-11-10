#!/bin/bash

for asn in "$@"
do
    whois -h whois.radb.net -i origin $asn | grep -oE "\b([0-9]{1,3}\.){3}[0-9]{1,3}\/[0-9]{1,2}\b"
done
