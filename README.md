# Stalker
Threat Intel and Incident Reponse

** WORK VERY MUCH IN PROGRESS **

First things first.
Opensource threat intelligence from Zeus Tracker, Malc0de, Bambenek and Locky tracker will be collected and dumped it on a database.
At the same time I'm also going to collect data from FireEye ETP (cos it's going to be useful for me) and dump it on the same database.
Possibly I will collect critical Stack information as well to enrich the database with more info. 

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
