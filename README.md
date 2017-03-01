# Stalker
Threat Intel and Incident Reponse

** WORK VERY MUCH IN PROGRESS **

First things first.
Opensource threat intelligence collection from:

Malc0de - http://malc0de.com/bl/IP_Blacklist.txt

zeus Tracker -https://zeustracker.abuse.ch/blocklist.php?download=ipblocklist

Ransomeware - Tracker = https://ransomwaretracker.abuse.ch/downloads/LY_C2_IPBL.txt

Bambenek - http://osint.bambenekconsulting.com/feeds/c2-ipmasterlist-high.txt

Emerging Threats - https://rules.emergingthreats.net/blockrules/compromised-ips.txt

Talos Intelligence (Snort) - http://www.talosintelligence.com/feeds/ip-filter.blf 

Malwaredomains - http://mirror1.malwaredomains.com/files/immortal_domains.txt 

OpenPhish - https://openphish.com/feed.txt

Malware Domains List (DISABLED)  - http://www.malwaredomainlist.com/hostslist/hosts.txt
 
All the information will be inserted into a local MongoDB database.
At the same time I'm also going to collect data from FireEye ETP (cos it's going to be useful for me) and dump it on the same database.
Possibly I will collect critical Stack information as well to enrich the database with more info, and I'll create a function to add database intel into a Bro watchlist. 

Once useful information has been collected, it can be query or used for investigation.
But, my main purpose is to build modules to automatically grab information from the database and search Carbon Black and/or Splunk for possible compromises.  


Tested on:
- Ubuntu Linux 14.04
- Python 3.4.3

Dependencies:
- MongoDB
- pyMongo
- Critical Stack - Account and client (Optional)
- Bro IDS (Optional)
