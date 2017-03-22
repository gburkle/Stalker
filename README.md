# Stalker
Threat Intel and Incident Reponse

** WORK VERY MUCH IN PROGRESS **

First things first.
Opensource threat intelligence collection from:

malcode_url = 'http://malc0de.com/bl/IP_Blacklist.txt'
zeus_url = 'https://zeustracker.abuse.ch/blocklist.php?download=ipblocklist'
zeus_url_domains = 'https://zeustracker.abuse.ch/blocklist.php?download=domainblocklist'
abusedomains = 'https://ransomwaretracker.abuse.ch/downloads/RW_DOMBL.txt'
abuseips = 'https://ransomwaretracker.abuse.ch/downloads/RW_IPBL.txt'
bambenek_url = 'http://osint.bambenekconsulting.com/feeds/c2-ipmasterlist-high.txt'
emergingthreats_url = 'https://rules.emergingthreats.net/blockrules/compromised-ips.txt'
snorttalos_url = 'http://www.talosintelligence.com/feeds/ip-filter.blf'
malwaredomains_url = 'http://mirror1.malwaredomains.com/files/immortal_domains.txt'
maldomainlist_url = 'http://www.malwaredomainlist.com/hostslist/hosts.txt'
openphish_url = 'https://openphish.com/feed.txt'
phishtank_url = 'http://data.phishtank.com/data/online-valid.csv'

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
