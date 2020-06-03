#!/bin/sh
# based on this version http://www.timokorthals.de/?p=334
# adapted by Stéphane T.
# Optimized by Digital-Dev

# Name of database (will be downloaded with this name)
_input=badips.db

# Name of chain in iptables (Only change this if you have already a chain with this name)
_droplist=blacklist

# Maximum Protection (0)
# Persistent, Confirmed bad traffic (3)
# Overly Aggressive bad traffic (5)
_level=2

# Logged service (see www.badips.com for documentation)
_service=any

# Get the bad IPs
wget -qO- http://www.badips.com/get/list/${_service}/$_level > $_input || { echo "$0: Unable to download ip list."; exit 1; }

# Flush the IP Set.
ipset flush $_droplist

# Create our Blacklist
cat badips.db | sort -n > ips_tmp
grep -E -o "(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)" ips_tmp > ips_sorted || rm ips_tmp
echo "create $_droplist hash:ip family inet hashsize 131072 maxelem 5000000" >> blacklist.ipset
sed -e 's/^/add blacklist /' ips_sorted >> blacklist.ipset
rm $_input
rm ips_sorted
# Import blacklist to IPSET
ipset restore -! < blacklist.ipset

# Finally, insert or append our black list
iptables -C INPUT -m set --match-set $_droplist src -j LOG --log-prefix "Drop Bad IP List " || iptables -A INPUT -m set --match-set $_droplist src -j LOG
iptables -C INPUT -m set --match-set $_droplist src -j DROP || iptables -A INPUT -m set --match-set $_droplist src -j DROP

# Remove blacklist file
rm blacklist.ipset
exit 0
done