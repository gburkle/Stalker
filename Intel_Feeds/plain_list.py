'''
Created on Feb 24, 2017

@author: tesoro
'''
#import urllib.parse
import re, os, datetime
#from Database import connections as dbconnect
#sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

### REGEX to find URL
isitadomain = re.compile(r'^([a-z0-9]+(-[a-z0-9]+)*\.)+[a-z]{2,}$') 
isitahash = re.compile(r'(?=(\b[A-Fa-f0-9]{32}\b))')
isitanip = re.compile('\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}')
isitanemail = re.compile(r'[^@]+@[^@]+\.[^@]+')

today = datetime.datetime.now().strftime("%m-%d-%Y")

def plainMenu():
    cls()
    
    
    print ("""
############################# 
#___________________________#       
# Ingest Plain List of IoCs #
#___________________________#
#        MD5 Hash           #
#       Domain Name         #
#        IP Address         #
#         email             #
#                           #
#############################

Use this to ingest a raw list of IoCs from a plain text file.
If the file is not in the Stalker folder, use absolute path. 
 
 
""")
    try:
        plainfilefeed = plainIngest()
        return (plainfilefeed)
    except Exception: 
        pass
           

def plainIngest():
    plainfile = input("Enter the name of the file: ")
    intelsource = input("Intel source (Ex. ongisac, mandiant): ")
    plainfilefeed = {}
    
    ips = 0
    hashes = 0
    emails = 0
    domains = 0
    
#    coll = dbconnect.opensourcelistsColl()
    
    if os.path.exists(plainfile):
        try: 
            with open(plainfile, 'r') as f: 
                rawintelfeed = f.read().splitlines()
        except Exception as e: print ("Something wrong happened while trying to open the file.", e)                
    else: # End of "if os.path.exists"
        print ("File not found. Make sure the file is on the Stalker folder, or use absolute path.\n")
        
    for line in rawintelfeed:
        if not line:
            # Ignore blank lines
            continue
        elif re.match(isitanip, line):
            #print ("This is an IP", line)
            plainfilefeed[line] = {'type': 'Intel::ADDR', 'intelsource': intelsource, 'date': today, 'notes':['']}
            ips += 1
        elif re.match(isitahash, line):
            #print ("This is a HASH", line)
            plainfilefeed[line] = {'type': 'Intel::FILE_HASH', 'intelsource': intelsource, 'date': today, 'notes':['']}
            hashes += 1
        elif re.match(isitanemail, line):
            #print ("This is an email", line)
            plainfilefeed[line] = {'type': 'Intel::EMAIL', 'intelsource': intelsource, 'date': today, 'notes':['']}
            emails += 1
        elif re.match(isitadomain, line):
            #print ("This is a domain name!", line)
            plainfilefeed[line] = {'type': 'Intel::DOMAIN', 'intelsource': intelsource, 'date': today, 'notes':['']}
            domains += 1
        else:
            print ("I don't know what this is -> [%s]\nIt shall be ignored!\n- Press Enter to continue - \n" % line)
            input()
    
    print ("[%s] Ip addreses will be imported." % ips)
    print ("[%s] MD5 hashes will be imported." % hashes)
    print ("[%s] Email addresses will be imported." % emails)
    print ("[%s] Domain Names will be imported." % domains)
    print("\n")
    input ("Press Enter to continue....")
    
    return (plainfilefeed)

def cls(): 
    #try:
    #    os.system('cls') # For windows
    #except Exception as e: return
    try:
        os.system('clear') # For Linux
    except Exception: return

if __name__ == '__main__':
    plainMenu()