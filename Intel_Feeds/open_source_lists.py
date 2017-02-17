import sys, os
import urllib.request
import re
import datetime
import json

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

############################## Global Variables #####################################

ipPattern = re.compile('\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}')  # Match IP address RegEx

malcode_url = 'http://malc0de.com/bl/IP_Blacklist.txt'
zeus_url = 'https://zeustracker.abuse.ch/blocklist.php?download=ipblocklist'
locky_url = 'https://ransomwaretracker.abuse.ch/downloads/LY_C2_IPBL.txt'
bambenek_url = 'http://osint.bambenekconsulting.com/feeds/c2-ipmasterlist-high.txt'

today = datetime.datetime.now().strftime("%m-%d-%Y")


############################# Malc0de Black List ###################################
def malcode_feed( url ):
	malcode = {}
	try:
		feed = urllib.request.urlopen(url)
		for line in feed:
			ip = re.match(ipPattern,(line.strip().decode('utf-8')))
			if ip:
				malcode[ip.group(0)] = [{'Type' : ['Intel:ADDR'], 'IntelSource' : ['Malc0de'], 'Date' : today}]
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
				zeus[ip.group(0)] = [{ 'Type' : 'Intel::ADDR', 'IntelSource' : ['ZeuS Tracker'], 'Date' : today}]
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
                                locky[ip.group(0)] = [{ 'Type' : 'Intel:ADDR', 'IntelSource' : ['Ransomware Tracker'], 'Date' : today}]
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
				bambenek[ip.group(0)] = [{ 'Type' : 'Intel:ADDR', 'IntelSource' : ['Bambenek'], 'Date' : today}]
	except Exception as e: print ("Something went wrong fetching Bambenek list\n", e)
	return (bambenek)
########################################################################################


################ BUILD A MASTER FEEDS COMBINING ALL ######################################

def master_feed (malcode,zeus,locky,bambenek):
	masterfeed = {}
	masterfeed.clear()
	
	feeds = [malcode, zeus, locky, bambenek]

	for feed in feeds:
		#print (feed)
		#input()
		for k, value in feed.items():
			#print (k)
			#input()
			if k not in  masterfeed:
				masterfeed.update({k:value})
			else:
				#print ('key = ', k)
				#print ('value = ', value)
				#print ('type in masterfeed = ', masterfeed[k][0]['Type'])
				#print ('type in feed = ', feed[k][0]['Type'])
				#types = masterfeed[k][0]['Type'] + feed[k][0]['Type']
				intel = masterfeed[k][0]['IntelSource'] + feed[k][0]['IntelSource']
				#masterfeed[k][0]['Type'] = types
				masterfeed[k][0]['IntelSource'] = intel
				#print (masterfeed[k])
				#input()


	return (masterfeed)

###########################################################################################


############## MAIN FUNCTION FETCH ALL FEEDS AND RETURN A MASTER FEED DICTIONARY #########
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

	return (master_feed(malcode,zeus,locky,bambenek))
##########################################################################################

if __name__ == '__main__':
	fetch_feeds()
	#print (master)
