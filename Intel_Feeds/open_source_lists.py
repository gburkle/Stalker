import sys, os
import urllib.request
#import urllib.parse
import re
import datetime
#from progressbar import ProgressBar
#import json

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

###### ADD A NEW FEED ####################
# 1 - Add url and feed to global variables
# 2 - Create feed collection function
# 3 - Add a feed fetch
# 4 - Add feed to master feed processing
############################## Global Variables #####################################
### STEP ONE
ipPattern = re.compile('\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}')  # Match IP address RegEx
isComment = re.compile('#')

malcode_url = 'http://malc0de.com/bl/IP_Blacklist.txt'
zeus_url = 'https://zeustracker.abuse.ch/blocklist.php?download=ipblocklist'
locky_url = 'https://ransomwaretracker.abuse.ch/downloads/LY_C2_IPBL.txt'
bambenek_url = 'http://osint.bambenekconsulting.com/feeds/c2-ipmasterlist-high.txt'
emergingthreats_url = 'https://rules.emergingthreats.net/blockrules/compromised-ips.txt'
snorttalos_url = 'http://www.talosintelligence.com/feeds/ip-filter.blf'
malwaredomains_url = 'http://mirror1.malwaredomains.com/files/immortal_domains.txt'
maldomainlist_url = 'http://www.malwaredomainlist.com/hostslist/hosts.txt'

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
def zeus_feed( url ):
	zeus = {}
	try:
		feed = urllib.request.urlopen(url)
		for line in feed:
			ip = re.match(ipPattern,(line.strip().decode('utf-8')))
			if ip:
				zeus[ip.group(0)] = { 'type' : 'Intel::ADDR', 'intelsource' : ['ZeuSTracker'], 'date' : today}
	except Exception as e: print ("Something went wrong fetching ZeuS tracker list\n", e)
	return (zeus)
#####################################################################################

################## Locky Ransomeware C2 URL Blocklist#####################################
def locky_feed( url ):
	locky = {}
	try:
		feed = urllib.request.urlopen(url)
		for line in feed:
			ip = re.match(ipPattern,(line.strip().decode('utf-8')))
			if ip:
				locky[ip.group(0)] = { 'type' : 'Intel::ADDR', 'intelsource' : ['RansomwareTracker'], 'date' : today}
	except Exception as e: print ("Something went wrong fetching Locky C2 list\n", e)
	return (locky)
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
	#justurl = re.compile(r"b\'(.*)\\n\'")
	try:
		feed = urllib.request.urlopen(url)
		for line in feed:
			if re.match(isComment,(line.strip().decode('utf-8'))):
				pass
			else:
				cleandomain = line.strip().decode('utf-8')
				#cleandomain = re.match(justurl, domain).group(1)
				#print (cleandomain)
				maldomains[cleandomain] = {'type' : 'Intel::DOMAIN', 'intelsource' : ['MalwareDomains'], 'date' : today}
				#print(domain)
				
	except Exception as e: print ("Something went wrong fetching the Immortal list of Malware URLs feed\n", e)
	return (maldomains)

#################### Malware Domain List DISABLED ################################################
#
#def malDomainList( url ):
#	pass
#	maldomaindic = {}
#	justurl = re.compile('127\.0\.0\.1 (.*)')
#	try:
#		feed = urllib.request.urlopen(url)
#		for line in feed:
#			#print (line.strip().decode('utf-8'))
#			if re.match(isComment,(line.strip().decode('utf-8'))):
#				pass
#			else:
#				#cleandomain = line.strip().decode('utf-8')
#				cleandomain = re.search(justurl, (line.strip().decode('utf-8')))
#				#### WHY IS NOT WORKING???
#				print(cleandomain.group())
#	except Exception as e: print ("Something went wrong fetching the Malware Domain list feed\n", e)
#	
#
#

############## MAIN FUNCTION FETCH ALL FEEDS AND RETURN A MASTER FEED DICTIONARY #########
## STEP THREE
def fetch_feeds():

	print ("\nFetching Malc0de Blackist ..... ", end="")
	malcode = malcode_feed( malcode_url )
	print ("[DONE]")

	print ("\nFetching ZeuS IP tracker IP list ....", end="")
	zeus = zeus_feed( zeus_url )
	print ("[DONE]")

	print ("\nFetching Locky Ransomware C2 blocklist ......", end="")
	locky = locky_feed( locky_url )
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
	
	print ("\nFetching Malware Domains list from Malaredomainlist.com .....", end="")
	#maldomainlist = malDomainList( maldomainlist_url)
	print ("[DISABLED]")
	
	## SETP ONE - ADD NEW FEEDS HERE
	return (master_feed(malcode,zeus,locky,bambenek,et,snort,malwaredomains))



################ FORGE A MASTER FEEDS AND INTO THE DARKNESS, BIND THEM ######################################
### STEP FOUR
def master_feed (malcode,zeus,locky,bambenek,et,snort,malwaredomains): ## ADD NEW FEEDS HERE AND IN THE FEED LIST DOWN BELOW
	masterfeed = {}
	masterfeed.clear()
	cachefile = '.cache/osintel'
	
		
	feeds = [malcode, zeus, locky, bambenek, et, snort, malwaredomains] ## ADD NEW FEED HERE
	print("\n")
	print ("Digesting Feeds....This might take some time if it's the first update or if you haven't updated in a while!\n")
	
	
	### CHECK FOR CACHE FILE TO IMPROVE DIGEST SPEED
	if os.path.exists(cachefile):
		#print ("cache file found!\n")
		
		cachelist = {}
		with open(cachefile) as f:
			for line in f:
				cachelist[line.strip()] = 'cache'
				
		#for k, value in cachelist.items():
		#	print (k)
		#	print (value)
			
			
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
				#cf.write('\n')
				if k not in  masterfeed:
					masterfeed.update({k:value})
				else:
					intel = masterfeed[k]['intelsource'] + feed[k]['intelsource']
					masterfeed[k]['intelsource'] = intel

		cf.close()
	
	## RETURN MASTER FEED 
	return (masterfeed)

###################### Improving digest speed - WORK IN PROGRES ###################################
#
#
#def master_feed2 (malcode,zeus,locky,bambenek,et,snort,malwaredomains):
#	masterfeed = {}
#	feeds = [malcode, zeus, locky, bambenek, et, snort, malwaredomains]
#	
#	pbar = ProgressBar()
#	
#	def digest(kargvs):
#		for feed in pbar(kargvs):
#			for k, v in feed.items():
#				pass
#	
#	
#	digest(feeds)
#
#
###########################################################################################

##########################################################################################

if __name__ == '__main__':
	fetch_feeds()
	#print (master)
