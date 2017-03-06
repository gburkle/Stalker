from Database import connections as dbconnect
from Modules import misc

####### REFERENCE FOR QUERIES

# Open source Intel feeds 
#'type' : 'Intel::ADDR'
#'type' : 'Intel::DOMAIN'
#'type' : 'Intel::FILE_HASH'
#'type' : 'Intel::EMAIL'
# 'intelsource' : 
    # Malc0de
    # ZeuSTracker
    # RansomwareTracker
    # Bambenek
    # Emerging_Threats
    # Snort_Talos
    # MalwareDomains
    # OpenPhish
    # MalwareDomainList
    # PhishTank
# 'date' : ''
# 'notes' : '[name | evilips | etpalert]'
#
# FireEye ETP
# Time, From, Recipients, Subject, Type, Name "name of the binary file, or full URL", MD5, evilips[] 
# key, 'time': '', 'dbtime': '', 'from': '', 'recipients':'', 'subject':'', 'type':'', 'name':'', 'md5':'', 'evilips':''
# type = doc','exe','zip','jar','htm','7zip','com','pdf','docx','xls','xlsx','js','vbs','ace','rar', 'bz2','bz','docm', 'scr', 'url



def dbStatistics():
    
    opensourcecoll = dbconnect.opensourcelistsColl()
    feetpcoll = dbconnect.feEtpColl()
    
    misc.cls()
    
    print ("\n")
    
    totalindicators = opensourcecoll.count()
    typedomain = opensourcecoll.find({'type':'Intel::DOMAIN'}).count()
    typeip = opensourcecoll.find({'type':'Intel::ADDR'}).count()
    typehash = opensourcecoll.find({'type':'Intel::FILE_HASH'}).count()
    typeemail = opensourcecoll.find({'type':'Intel::EMAIL'}).count()
    feetptotal = opensourcecoll.find({'intelsource':'FireEye_ETP'}).count()
    ongtotal = opensourcecoll.find({'intelsource':'ongisac'}).count()
    malcodetotal = opensourcecoll.find({'intelsource':'Malc0de'}).count()
    zeustotal = opensourcecoll.find({'intelsource':'ZeuSTracker'}).count()
    rantracktotal = opensourcecoll.find({'intelsource':'RansomwareTracker'}).count()
    bambetotal = opensourcecoll.find({'intelsource':'Bambenek'}).count()
    ethreatstotal = opensourcecoll.find({'intelsource':'Emerging_Threats'}).count()
    talostotal = opensourcecoll.find({'intelsource':'Snort_Talos'}).count()
    mdomainstotal = opensourcecoll.find({'intelsource':'MalwareDomains'}).count()
    ophishtotal = opensourcecoll.find({'intelsource':'OpenPhish'}).count()
    mdomainlisttotal = opensourcecoll.find({'intelsource':'MalwareDomainList'}).count()
    phishtanktotal = opensourcecoll.find({'intelsource':'PhishTank'}).count()
    others = opensourcecoll.find({'intelsource':{"$nin":['FireEye_ETP','ongisac','Malc0de','ZeuSTracker','RansomwareTracker','Bambenek','Emerging_Threats',\
                                                       'Snort_Talos','MalwareDomains','OpenPhish','MalwareDomainList','PhishTank']}}).count()
    otherTypes = opensourcecoll.find({'intelsource':{"$nin":['FireEye_ETP','ongisac','Malc0de','ZeuSTracker','RansomwareTracker','Bambenek','Emerging_Threats',\
                                                       'Snort_Talos','MalwareDomains','OpenPhish','MalwareDomainList','PhishTank']}})
    
    inteltypes = set()
    for t in otherTypes:
        inteltypes.add(str(t['intelsource']))
   
    
    print ("""
  _________________________________________________________________________________________________
::
::                     ----- Threat Intelligence Info -------
::
:: Total Number of indicators: %s
::
:: Domains: %s   |   IPs: %s   |   Hash: %s   |   Email: %s
::
:: From FireEye ETP: %s   |   From ONG-ISAC: %s   
:: ____________________________________________________________________________________________________
:: 
::                            Open Source Threat Feeds
::                           --------------------------
:: Malc0de: %s            |   ZeuS Tracker: %s     |   Ransomeware Tracker: %s   |   Bambenek: %s
::
:: Emerging Threats: %s   |   Talos Security: %s   |   Immortal Malware Domains: %s
::
:: OpenPhish: %s          |   Malware Domain List: %s   |   Phish Tank: %s      
::
:: Others: %s : %s
:: _____________________________________________________________________________________________________
""" % (totalindicators,typedomain,typeip,typehash,typeemail,feetptotal,ongtotal,malcodetotal,\
       zeustotal,rantracktotal,bambetotal,ethreatstotal,talostotal,mdomainstotal,ophishtotal,mdomainlisttotal,phishtanktotal,others,inteltypes))
    
    feetptotal = feetpcoll.count() 
    typeurl = feetpcoll.find({'type':'url'}).count()
    typedoc = feetpcoll.find({'type':'doc'}).count()
    typeexe = feetpcoll.find({'type':'exe'}).count()
    typezip = feetpcoll.find({'type':'zip'}).count()
    typejar = feetpcoll.find({'type':'jar'}).count()
    typehtm = feetpcoll.find({'type':'htm'}).count()
    type7zip = feetpcoll.find({'type':'7zip'}).count()
    typecom = feetpcoll.find({'type':'com'}).count()
    typepdf = feetpcoll.find({'type':'pdf'}).count()
    typedocx = feetpcoll.find({'type':'docx'}).count()
    typexls = feetpcoll.find({'type':'xls'}).count()
    typexlsx = feetpcoll.find({'type':'xlsx'}).count()
    typejs = feetpcoll.find({'type':'js'}).count()
    typevbs = feetpcoll.find({'type':'vbs'}).count()
    typeace = feetpcoll.find({'type':'ace'}).count()
    typerar = feetpcoll.find({'type':'rar'}).count()
    typebz2 = feetpcoll.find({'type':'bz2'}).count()
    typebz = feetpcoll.find({'type':'bz'}).count()
    typedocm = feetpcoll.find({'type':'docm'}).count()
    typescr = feetpcoll.find({'type':'scr'}).count()
    othersfe = feetpcoll.find({'type':{"$nin":['url','doc','exe','zip','jar','htm','7zip','com','pdf','docx','xls','xlsx','js',\
                                               'vbs','ace','rar','bz2','bz','docm','scr']}}).count()
                                               
    otherFtypes = feetpcoll.find({'type':{"$nin":['url','doc','exe','zip','jar','htm','7zip','com','pdf','docx','xls','xlsx','js',\
                                               'vbs','ace','rar','bz2','bz','docm','scr']}})
                                               
                                               
    filetypes = set()
    for t in otherFtypes:
        filetypes.add(str(t['type']))                                           
                                               
    print ("""
  ______________________________________________________________________________________________
::                                                                                  
::                  - FireEye Email Threat Prevention Info -                        
::                                                                                  
:: Total Number of Records: %s                                                                
::                                                                                  
:: URLs: %s  |  Zip: %s  |  Jar: %s   |  Doc: %s  |  Exe: %s   |  Htm: %s  |  7zip: %s      
::                                                                                    
:: Com: %s   |  Pdf: %s  |  docx: %s  |  xls: %s  |  xlsx: %s  |  js: %s   |  vbs: %s       
::                                                                                  
:: Ace: %s   |  Rar: %s  |  Bz2: %s   |  bz: %s   |  Docm: %s  |  Scr: %s   
::
:: Other: %s : %s         
::                                                                                  
::________________________________________________________________________________________________
""" % (feetptotal, typeurl, typezip, typejar, typedoc, typeexe, typehtm, type7zip, typecom, typepdf, \
       typedocx, typexls, typexlsx, typejs, typevbs, typeace, typerar, typebz2, typebz, typedocm, typescr,othersfe,filetypes))
    
    
    
    
    
    print("\n")
    input("Press Enter to continue...")
    
    misc.cls()

if __name__ == '__main__':
    pass
