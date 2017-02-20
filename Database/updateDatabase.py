'''
Created on Feb 16, 2017

@author: tesoro
'''
import sys, os
#import json
from  Intel_Feeds import open_source_lists as feeds
from Intel_Feeds import fireeye_export_list as fireeye

from pymongo import MongoClient
#from bson.objectid import ObjectId
#from pprint import pprint

# ======MongoDB connection to intelFeeds Collection================
def dbConnect():
    try:
        client = MongoClient()
        db = client.intelFeeds
        coll = db.opensourcelists
    except Exception as e: 
        print ("Could not connect to the IntelFeeds Database", e)
        sys.exit(0)
        
    return (coll)
# ================================================================       

# ==========MongoDB connection to fireeyeETP Collection ==========
def dbConnect2():
    try:
        client = MongoClient()
        db = client.fireeyeETP
        coll = db.etpalerts
    except Exception as e:
        print ("Coult not connect to the FireEye ETP Databese", e)
        sys.exit(0)
        
    return (coll)
# ==================================================================

def dbMenu():
    
    def options():
        print ("""
[1] Update Open Source Feeds. (Malc0de, Zeus Tracker, Locky and Bambenek).
[2] Update FireEye ETP.
[3] Update Critical Stack Feed.
[4] Back to main menu. 
""")
    options()
    while True:
        try:
            option = int(input("Option: "))
        except Exception: 
            #print ("Was that even a number? \n")
            option = 0
        if option == 1:
            dbUpdate_opensourcelists()
            options()
        elif option == 2:
            dbUpdate_FireeyeETP()
            options()
        elif option == 3:
            print ("NOT YET IMPLEMENTED!\n")
        elif option == 4:
            break
        else:
            print ("That doesn't seem to be an option. \n")
            options()
            

# ================================================================================================================================================
# Update MongoDB Database "IntelFeeds", Collection "opensourcelists" with information from Malc0de, Zeus Tracker, Locky and Bambenek

def dbUpdate_opensourcelists():
    
    stats = 0
    coll = dbConnect()
    
    print ("Downloading and inserting into the database information from open source lists (Malc0de, Zeus Tracker, Locky and Bambenek) ...\n")
    try:
        
        for key, value in feeds.fetch_feeds().items():
            #print ('IP = ', key)
            #print ('Intel = ', value)
            if coll.find({'indicator':key}).count() > 0:
                #print ("Indicator already in database\n")
                pass
            else:
                try:
                    data = {'indicator': key, 'type': value['Type'], 'intelsource': value['IntelSource'], 'date': value['Date'], 'notes':['']}
                    coll.insert(data)
                    stats += 1
                except Exception as e: print(key, " could not be inserted into the database!!", e)
            
                     
    except Exception as e: print("Could not update database with Open Source Lists information", e)
    
    if stats == 0:
        print ("\n")
        print ("No information was inserted into the Intel Feeds database. ¯\_(ツ)_/¯ \n")
    else:
        print ("\n")
        print (stats, "new records were inserted into the database from open source lists (Malc0de, Zeus Tracker, Locky and Bambenek).\n")
        
    
#=============================================================================================================================================================
# Read FireEye ETP CSV alerts file with structure:
# Alert ID,Message ID,Date & Time,From,Recipients,Subject,Malware Type,Malware File Type,Malware Name,Malware MD5,Malware Analysis Application,\
# Malware Analysis OS,Virus Total,Source IP,Source Country,Malware Comunication IP,Malware Communication Countries,Email Status,Threat Type,Risk Level
#
# This creates a separate FireEye ETP database in MongoDB and updates intelFeeds database with IOCs from the file. 
# It uses "Intel_Feeds\fireeye_export_list.py" to generate the dictionary list used to update databases. 

## Dictionary name: etpalerts.
## Key = ETP Alert number
## Value = { Time, From, Recipients, Subject, Type, Name "name of the binary file, or full URL", MD5, evilips[] }

def dbUpdate_FireeyeETP():
    
    coll = dbConnect2()
    stats = 0
    file = input("Enter the name of the file containing ETP alerts in CSV form. (Include absolute path if file is not in Stalker folder): ")
    
    if os.path.exists(file):
        etpalerts = fireeye.readETP(file)
        try:
            print("\n")
            print("Updating FireEye ETP database....")        
            for key, value in etpalerts.items():
                if coll.find({'alert': key}).count() > 0:
                    #print ("Alert already in database")
                    #print (key)
                    #print (value)
                    pass
                else:
                    data = {'alert': key, 'time': value['Time'], 'from': value['From'], 'recipients':value['Recipients'], 'subject':value['Subject'], 'type':value['Type'], 'name':value['Name'], 'md5':value['MD5'], 'evilips':value['evilips'] }
                    #print (data)
                    coll.insert(data)
                    stats += 1
                    
        except Exception as e: print ("Something went wrong while updating FireEye ETP database!", e) 
        
        if stats == 0:
            print ("\n")
            print ("Nothing new found. No information was inserted into the database. ¯\_(ツ)_/¯ \n")
        else:
            print ("\n")
            print (stats, "new records were inserted into the database from the FireEye ETP alerts file.\n")
            
## End of importing data from alerts file into FireETP database.
## Next we will use the same information to update Intel Feeds database with ETP information.             
            
        try:
            print("\n")
            print("Updating Intel Feed database with ETP information.....")
            stats = 0
            
            for key, value in etpalerts.items():
                if 1 == 1:
                    pass
                   #print (key)
                   #print (value)
                else:
                    pass
            
            
        except Exception as e: print ("Something went wrong while updating Intel Feeds database with ETP information.", e)   
        
        if stats == 0:
            print ("\n")
            print ("Nothing new found. No information was inserted into the database. ¯\_(ツ)_/¯ \n")
        else:
            print ("\n")
            print (stats, "new records were inserted into the Intel Feeds database from the FireEye ETP alerts file.\n")
            
             
    else: # End of "if os.path.exists"
        print ("File not found. Make sure the file is on the Stalker folder, or use absolute path.\n")
     
    

# ================================================================================================================================================================
if __name__ == '__main__':
    dbMenu()
    