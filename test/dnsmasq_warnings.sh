#!/bin/bash

# Walk files in sorted order to prevent filesystem
# differences as alphabetical sorting isn't guaranteed

echo -n "" > /tmp/dnsmasq_warnings
readarray -d '' files < <(printf '%s\0' src/dnsmasq/* | sort -zd)
for filename in "${files[@]}"; do
  awk '{
    if ($0 ~ /LOG_WARNING,/) {
      triggered=1;
      print FILENAME;
    }
    if (triggered) {
       print;
       if ($0 ~ /\);/) {
  	triggered=0;
       }
    }
  }' "$filename" >> /tmp/dnsmasq_warnings
done

diff test/dnsmasq_warnings /tmp/dnsmasq_warnings
