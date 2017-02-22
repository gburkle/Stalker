'''
Created on Feb 22, 2017

@author: tesoro
'''
from Database import connections as dbconnect
import os
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
    
    cls()
    
    print (" ######## FireEye ETP Database Collection Statistics #########\n")
    feetptotal = feetpcoll.count()
    print ("Total number of record on FireEye ETP Collection: ", feetptotal)
    print ("\n")
    
    typeurl = feetpcoll.find({'type':'url'}).count()
    print ("Total number of URL's on FireEye ETP Collection: ", typeurl)
    
    typedoc = feetpcoll.find({'type':'doc'}).count()
    print ("Total number of \"DOC\" files on FireEye ETP Collection: ", typedoc)
    
    typeexe = feetpcoll.find({'type':'exe'}).count()
    print ("Total number of \"EXE\" files on FireEye ETP Collection: ", typeexe)
    
    typezip = feetpcoll.find({'type':'zip'}).count()
    print ("Total number of \"ZIP\" files on FireEye ETP Collection: ", typezip)
    
    typejar = feetpcoll.find({'type':'jar'}).count()
    print ("Total number of \"JAR\" files on FireEye ETP Collection: ", typejar)
    
    typehtm = feetpcoll.find({'type':'htm'}).count()
    print ("Total number of \"HTM\" files on FireEye ETP Collection: ", typehtm)
    
    type7zip = feetpcoll.find({'type':'7zip'}).count()
    print ("Total number of \"7ZIP\" files on FireEye ETP Collection: ", type7zip)
    
    typecom = feetpcoll.find({'type':'com'}).count()
    print ("Total number of \"COM\" files on FireEye ETP Collection: ", typecom)
    
    typepdf = feetpcoll.find({'type':'pdf'}).count()
    print ("Total number of \"PDF\" files on FireEye ETP Collection: ", typepdf)
    
    typedocx = feetpcoll.find({'type':'docx'}).count()
    print ("Total number of \"DOCX\" files on FireEye ETP Collection: ", typedocx)
    
    typexls = feetpcoll.find({'type':'xls'}).count()
    print ("Total number of \"XLS\" files on FireEye ETP Collection: ", typexls)
    
    typexlsx = feetpcoll.find({'type':'xlsx'}).count()
    print ("Total number of \"XLSX\" files on FireEye ETP Collection: ", typexlsx)
    
    typejs = feetpcoll.find({'type':'js'}).count()
    print ("Total number of \"JS\" files on FireEye ETP Collection: ", typejs)
    
    typevbs = feetpcoll.find({'type':'vbs'}).count()
    print ("Total number of \"VBS\" files on FireEye ETP Collection: ", typevbs)
    
    typeace = feetpcoll.find({'type':'ace'}).count()
    print ("Total number of \"ACE\" files on FireEye ETP Collection: ", typeace)
    
    typerar = feetpcoll.find({'type':'rar'}).count()
    print ("Total number of \"RAR\" files on FireEye ETP Collection: ", typerar)
    
    typebz2 = feetpcoll.find({'type':'bz2'}).count()
    print ("Total number of \"BZ2\" files on FireEye ETP Collection: ", typebz2)
    
    typebz = feetpcoll.find({'type':'bz'}).count()
    print ("Total number of \"BZ\" files on FireEye ETP Collection: ", typebz)
    
    typedocm = feetpcoll.find({'type':'docm'}).count()
    print ("Total number of \"DOCM\" files on FireEye ETP Collection: ", typedocm)
    
    typescr = feetpcoll.find({'type':'scr'}).count()
    print ("Total number of \"SCR\" files on FireEye ETP Collection: ", typescr)
    
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
    cls()

def cls(): 
    #try:
    #    os.system('cls') # For windows
    #except Exception as e: return
    try:
        os.system('clear') # For Linux
    except Exception: return

if __name__ == '__main__':
    pass