'''
Created on Feb 22, 2017

@author: tesoro
'''
from Database import connections as dbconnect
from Modules import misc
#import os
# REFERENCE FOR QUERIES
# Open source Intel feeds 
#'type' : 'Intel::ADDR'
#'type' : 'Intel::DOMAIN'
#'type' : 'Intel::FILE_HASH'
# 'intelsource' : '[FireEye_ETP | Malc0de | ZeuS Tracker | Ransomware Tracker | Bambenek | Emerging_Threats]'
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
::_____________________________________________________________________________________________
""" % (feetptotal, typeurl, typezip, typejar, typedoc, typeexe, typehtm, type7zip, typecom, typepdf, \
       typedocx, typexls, typexlsx, typejs, typevbs, typeace, typerar, typebz2, typebz, typedocm, typescr))
    
    
    
    print ("\n")
    print ("####### OpenSource Threat Intel Collection Statistics #######\n")
    
    opensourcetotal = opensourcecoll.count()
    print ("Total number of records on Open Source Collection: ", opensourcetotal)
    print ("\n")
    
    typeip = opensourcecoll.find({'type':'Intel::ADDR'}).count()
    print ("Total number of IP addresses on Open Source Collection: ", typeip)
    
    typeurl = opensourcecoll.find({'type':'Intel::DOMAIN'}).count()
    print ("Total number of Domain Names on Open Source Collection: ", typeurl)
    
    typehash = opensourcecoll.find({'type':'Intel::FILE_HASH'}).count()
    print ("Total number of HASHES on Open Source Collection: ", typehash)
    
    print("\n")
    input("Press Enter to continue...")
    
    misc.cls()

if __name__ == '__main__':
    pass