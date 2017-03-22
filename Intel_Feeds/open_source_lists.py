import sys, os
import urllib.request
import urllib.parse
import re, csv
import datetime
#from Intel_Feeds.plain_list import isitadomain
#from smtplib import line
#from progressbar import ProgressBar
#import json

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

###### ADD A NEW FEED ####################
# 1 - Add url and feed to global variables
# 2 - Create feed collection function
# 3 - Add a feed fetch
# 4 - Add feed to master feed processing
# 5 - Add information to statistics (OPTIONAL)
############################## Global Variables #####################################
### STEP ONE
ipPattern = re.compile('\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}')  # Match IP address RegEx
isitadomain = re.compile(r'^([a-z0-9]+(-[a-z0-9]+)*\.)+[a-z]{2,}$') # Match Domain name
isComment = re.compile('#')

malcode_url = 'http://malc0de.com/bl/IP_Blacklist.txt'
zeus_url = 'https://zeustracker.abuse.ch/blocklist.php?download=ipblocklist'
zeus_url_domains = 'https://zeustracker.abuse.ch/blocklist.php?download=domainblocklist'
#locky_url = 'https://ransomwaretracker.abuse.ch/downloads/LY_C2_IPBL.txt'
abusedomains = 'https://ransomwaretracker.abuse.ch/downloads/RW_DOMBL.txt'
abuseips = 'https://ransomwaretracker.abuse.ch/downloads/RW_IPBL.txt'
bambenek_url = 'http://osint.bambenekconsulting.com/feeds/c2-ipmasterlist-high.txt'
emergingthreats_url = 'https://rules.emergingthreats.net/blockrules/compromised-ips.txt'
snorttalos_url = 'http://www.talosintelligence.com/feeds/ip-filter.blf'
malwaredomains_url = 'http://mirror1.malwaredomains.com/files/immortal_domains.txt'
maldomainlist_url = 'http://www.malwaredomainlist.com/hostslist/hosts.txt'
openphish_url = 'https://openphish.com/feed.txt'
phishtank_url = 'http://data.phishtank.com/data/online-valid.csv'

today = datetime.datetime.now().strftime("%m-%d-%Y")

################# FEED COLLECTION FUCTIONS ########################################
### SETP TWO
############################# Malc0de Black List ###################################

def malcode_feed( url ):
	malcode = {}
	try:
		feed = urllib.request.urlopen(url)
		for line in feed:
			ip = re.match(ipPattern,(line.strip().decode('utf-8')))
			if ip:
				malcode[ip.group(0)] = {'type' : ['Intel::ADDR'], 'intelsource' : ['Malc0de'], 'date' : today}
	except Exception as e: print ("Something went wrong fetching Malc0de Blacklist\n", e)
	return (malcode)
####################################################################################

########################### ZeuS Tracker List #####################################
def zeus_feed( url, url2 ):
	zeus = {}
	try:
		ip_feed = list(urllib.request.urlopen(url))		
		domain_feed = list(urllib.request.urlopen(url2))
		
		allfeeds = ip_feed + domain_feed
		
		for line in allfeeds:
			indicator = line.strip().decode('utf-8')
			if not indicator:
				# Ignore blank lines
				continue
			elif re.match(isComment,(indicator)):
				continue
			elif re.match(ipPattern,(indicator)):
				zeus[indicator] = { 'type' : 'Intel::ADDR', 'intelsource' : ['ZeuSTracker'], 'date' : today}
			elif re.match(isitadomain,(indicator)):
				zeus[indicator] = { 'type' : 'Intel::DOMAIN', 'intelsource' : ['ZeuSTracker'], 'date' : today}
			else:
				continue
				#print ("I dont know what this [%s] is!! It shall be ignored. " % indicator)
	except Exception as e: print ("Something went wrong fetching ZeuS tracker list\n", e)
	return (zeus)
#####################################################################################

##################  Ransomeware Tracker abuse.ch C2 #####################################
def abuse_feed( url, url2 ):
	abuse = {}
	
	try:
		ip_feed = list(urllib.request.urlopen(url))		
		domain_feed = list(urllib.request.urlopen(url2))
		
		allfeeds = ip_feed + domain_feed
		
		for line in allfeeds:
			indicator = line.strip().decode('utf-8')
			if not indicator:
				# Ignore blank lines
				continue
			elif re.match(isComment,(indicator)):
				continue
			elif re.match(ipPattern,(indicator)):
				abuse[indicator] = { 'type' : 'Intel::ADDR', 'intelsource' : ['RansomwareTracker'], 'date' : today}
			elif re.match(isitadomain,(indicator)):
				abuse[indicator] = { 'type' : 'Intel::DOMAIN', 'intelsource' : ['RansomwareTracker'], 'date' : today}
			else:
				continue
				#print ("I dont know what this [%s] is!! It shall be ignored. " % indicator)
			
	except Exception as e: print ("Something went wrong fetching Abuse.ch Ransomeware Tracker list\n", e)
	return (abuse)

#####################################################################################

############ Bambenek Consulting Master Feed of known active C&C IPs ################
def bambenek_feed ( url ):
	bambenek = {}
	try:
		feed = urllib.request.urlopen(url)
		for line in feed:
			ip = re.match(ipPattern,(line.strip().decode('utf-8')))
			if ip:
				bambenek[ip.group(0)] = { 'type' : 'Intel::ADDR', 'intelsource' : ['Bambenek'], 'date' : today}
	except Exception as e: print ("Something went wrong fetching Bambenek list\n", e)
	return (bambenek)
########################################################################################

############ Emerging Threats Feed of known compromised IP addresses ##############
def emerging_threats( url ):
	et = {}
	try:
		feed = urllib.request.urlopen(url)
		for line in feed:
			ip = re.match(ipPattern,(line.strip().decode('utf-8')))
			if ip:
				et[ip.group(0)] = {'type' : 'Intel::ADDR', 'intelsource' : ['Emerging_Threats'], 'date' : today}
	except Exception as e: print ("Something went wrong fetching Emerging Threats list\n", e)
	return (et)

##############################################################################################

############## Snort Talos Intelligence #####################################################
def snortTalos( url ):
	snort = {}
	try:
		feed = urllib.request.urlopen(url)
		for line in feed:
			ip = re.match(ipPattern,(line.strip().decode('utf-8')))
			if ip:
				snort[ip.group(0)] = {'type' : 'Intel::ADDR', 'intelsource' : ['Snort_Talos'], 'date' : today}
	except Exception as e: print ("Something went wrong fetching Talos Intelligence Snort feed\n", e)
	return (snort)

##############################################################################################

################ Immortal Malware Domains ###################################################
def malwareDomains( url ):
	maldomains = {}
	try:
		feed = urllib.request.urlopen(url)
		for line in feed:
			if re.match(isComment,(line.strip().decode('utf-8'))):
				continue
			else:
				cleandomain = line.strip().decode('utf-8')
				maldomains[cleandomain] = {'type' : 'Intel::DOMAIN', 'intelsource' : ['MalwareDomains'], 'date' : today}

				
	except Exception as e: print ("Something went wrong fetching the Immortal list of Malware URLs feed\n", e)
	return (maldomains)

################ OpenPhish list of phishing sites #################################################
def openPhish( url ):
	ophish = {}
	try:
		feed = urllib.request.urlopen(url)
		for line in feed:
			line = line.strip().decode('utf-8')
			cleanurl = urllib.parse.urlparse(line, scheme='http|https')
			#print (cleanurl[1])
			ophish[cleanurl[1]] = {'type': 'Intel::DOMAIN', 'intelsource': ['OpenPhish'], 'date': today}
			
	except Exception as e: print ("Something went wrong fetch OpenPhish list of phishing sites\n", e)
	return (ophish)

#################### Malware Domain List DISABLED ################################################
#
def malDomainList( url ):
	maldomainlist = {}
	home = re.compile('127\.0\.0\.1  ')
	try:
		feed = urllib.request.urlopen(url)
		for line in feed:
			#print (line.strip().decode('utf-8'))
			if re.match(isComment,(line.strip().decode('utf-8'))):
				continue
			else:
				line = (line.strip().decode('utf-8'))
				line = (re.sub(home, 'http://', line))
				cleanurl = urllib.parse.urlparse(line)
				#print(cleanurl[1])
				maldomainlist[cleanurl[1]] = {'type': 'Intel::DOMAIN', 'intelsource': ['MalwareDomainList'], 'date': today}
				
	except Exception as e: print ("Something went wrong fetching the Malware Domain list feed\n", e)
	return (maldomainlist)
#
################# Phish Tank ###########################
def phishTank( url ):
	phishtankdic = {}
	headerline = re.compile('phish_id')
	
	try:
		feed = urllib.request.urlopen(url)	
		for line in feed:
			if re.match(headerline, (line.strip().decode('utf-8'))):
				# Ignore header line
				continue
			else:
				line = line.strip().decode('utf-8')
				linea =csv.reader(line.splitlines())
				for element in linea:
					cleanurl = urllib.parse.urlparse((element[1]))
					phishtankdic[cleanurl[1]] = {'type': 'Intel::DOMAIN', 'intelsource': ['PhishTank'], 'date': today}
	
	except Exception as e: print ("Something went wrong fetching PhishTank feed\n", e)
	return (phishtankdic)

############## MAIN FUNCTION FETCH ALL FEEDS AND RETURN A MASTER FEED DICTIONARY #########
## STEP THREE
def fetch_feeds():

	print ("\nFetching Malc0de Blackist ..... ", end="")
	malcode = malcode_feed( malcode_url )
	print ("[DONE]")

	print ("\nFetching ZeuS IP tracker list of IPs and Domains ....", end="")
	zeus = zeus_feed( zeus_url, zeus_url_domains )
	print ("[DONE]")

	print ("\nFetching Abuse.ch Ransomware Tracker block lists ......", end="")
	abuse = abuse_feed( abuseips, abusedomains )
	print ("[DONE]")

	print ("\nFetching Bambenek Master feed of known C&C IP addresses .... ", end="")
	bambenek = bambenek_feed( bambenek_url )
	print ("[DONE]")
	
	print ("\nFetching Emerging Threats feed of Compromised IP addresses .... ", end="")
	et = emerging_threats( emergingthreats_url )
	print ("[DONE]")
	
	print ("\nFetching Talos Intelligence \"Snort\" black list of IP addresses .... ", end="")
	snort = snortTalos( snorttalos_url )
	print ("[DONE]")
	
	print ("\nFetching Immortal Malware Domains from Malwaredomains.com .....", end="")
	malwaredomains = malwareDomains( malwaredomains_url )
	print ("[DONE]")
	
	print ("\nFetching phishing sites from OpenPhish.com ....", end="")
	openphish = openPhish( openphish_url )
	print ("[DONE]")
	
	print ("\nFetching Malware Domains list from Malaredomainlist.com .....", end="")
	maldomainlist = malDomainList( maldomainlist_url)
	print ("[DONE]")
	
	print ("\nFetching PhishTank list of know phishing domains .....", end="")
	#phishtank = phishTank( phishtank_url )
	print ("[DISABLED]")
	
	## SETP ONE - ADD NEW FEEDS HERE
	return (master_feed(malcode,zeus,abuse,bambenek,et,snort,malwaredomains,openphish,maldomainlist))



################ FORGE A MASTER FEEDS AND INTO THE DARKNESS, BIND THEM ######################################
### STEP FOUR
def master_feed (malcode,zeus,abuse,bambenek,et,snort,malwaredomains,openphish,maldomainlist): ## ADD NEW FEEDS HERE AND IN THE FEED LIST DOWN BELOW
	masterfeed = {}
	masterfeed.clear()
	cachefile = '.cache/osintel'
	
		
	feeds = [malcode,zeus,abuse,bambenek,et,snort,malwaredomains,openphish,maldomainlist] ## ADD NEW FEED HERE
	print("\n______________________________________________________________________________________________________________________")
	print ("\nDigesting Feeds....This takes a LONG time if it's the first update, you haven't updated in a while, or you deleted the cache folder!\n")
	
	
	### CHECK FOR CACHE FILE TO IMPROVE DIGEST SPEED
	### IF YOU MAKE CHANGES DIRECTLY TO THE DATABASE MAKE SURE TO DELETE THE CACHE FOLDER!!!
	if os.path.exists(cachefile):
		#print ("cache file found!\n")
		cachelist = {}
		with open(cachefile) as f:
			for line in f:
				cachelist[line.strip()] = 'cache'
				
		cf2 = []
		for feed in feeds:
			for k, value in feed.items():
				cf2.append(str(k))
				if k not in cachelist:
					if k not in  masterfeed:
						masterfeed.update({k:value})
					else:
						intel = masterfeed[k]['intelsource'] + feed[k]['intelsource']
						masterfeed[k]['intelsource'] = intel	
				else:
					#print (k, "in cache list\n")
					continue
				
		# CREATE NEW CACHE FILE			
		cf = open(cachefile, 'w')
		for item in cf2:
			cf.write("%s\n" % item)				
		cf.close()		
	## IF NO CACHE FILE CREATE ONE 
	else:
		#print ("no cache file found!\n")
		os.makedirs('.cache/')
		cf = open(cachefile, 'w')	
		for feed in feeds:
			for k, value in feed.items():
				newline = ('%s\n' % str(k))	
				cf.write(newline)
				if k not in  masterfeed:
					masterfeed.update({k:value})
				else:
					intel = masterfeed[k]['intelsource'] + feed[k]['intelsource']
					masterfeed[k]['intelsource'] = intel

		cf.close()
	
	## RETURN MASTER FEED 
	return (masterfeed)

##########################################################################################
### RUN THIS SCRIPT BY ITELSF FOR TESTING
if __name__ == '__main__':
	fetch_feeds()
	#print (master)
