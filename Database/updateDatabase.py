'''
Created on Feb 16, 2017

@author: tesoro
'''
import sys, os
#import json
from  Intel_Feeds import open_source_lists as feeds
from Intel_Feeds import fireeye_export_list as fireeye

from pymongo import MongoClient
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
                    data = {'indicator': key, 'type': value[0]['Type'], 'intelsource': value[0]['IntelSource'], 'date': value[0]['Date'], 'notes':''}
                    coll.insert(data)
                    stats += 1
                except Exception as e: print(key, " could not be inserted into the database!!", e)
            
        #print ("\n", stats, " new records were inserted.\n")             
    except Exception as e: print("Could not update database with Open Source Lists information", e)
    
    if stats == 0:
        print ("\n")
        print ("No information was inserted into the database. ¯\_(ツ)_/¯ \n")
    else:
        print ("\n")
        print (stats, "new records were inserted into the database from open source lists (Malc0de, Zeus Tracker, Locky and Bambenek).\n")
        
    #cursor = coll.find({})
    #for document in cursor:
    #    pprint(document)
#=============================================================================================================================================================
# Read FireEye ETP CSV alerts file with structure:
# Alert ID,Message ID,Date & Time,From,Recipients,Subject,Malware Type,Malware File Type,Malware Name,Malware MD5,Malware Analysis Application,\
# Malware Analysis OS,Virus Total,Source IP,Source Country,Malware Comunication IP,Malware Communication Countries,Email Status,Threat Type,Risk Level
#
# This creates a separate FireEye ETP database in MongoDB and updates intelFeeds database with IOCs from the file. 


def dbUpdate_FireeyeETP():
    
    file = input("Enter the name of the file containing ETP alerts in CSV form. (Include absolute path if file is not in Stalker folder): ")
    
    if os.path.exists(file):
        etpalerts = fireeye.readETP(file)
        try:        
            for key, value in etpalerts.items():
                print (key)
                print (value)
        except Exception as e: print ("Something went terribly wrong!", e) 
        
    else:
        print ("File not found. Make sure the file is on the Stalker folder, or use absolute path.\n")
     
    

# ================================================================================================================================================================
if __name__ == '__main__':
    dbMenu()
    