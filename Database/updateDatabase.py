'''
Created on Feb 16, 2017

@author: tesoro
'''
import sys
#import json
from  Intel_Feeds import open_source_lists as feeds
from pymongo import MongoClient
#from pprint import pprint

# ======================================================
def dbConnect():
    try:
        client = MongoClient()
        db = client.intelFeeds
        coll = db.opensourcelists
    except Exception as e: 
        print ("Could not connect to the Database", e)
        sys.exit(0)
        
    return (coll)
# =====================================================        

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
                    data = {'indicator': key, 'type': value[0]['Type'], 'intelsource': value[0]['IntelSource'], 'date': value[0]['Date']}
                    coll.insert(data)
                    stats += 1
                except Exception as e: print(key, " could not be inserted into the database!!", e)
            
        #print ("\n", stats, " new records were inserted.\n")             
    except Exception as e: print("Could not update database with Open Source Lists information", e)
    
    if stats == 0:
        print ("\n")
        print ("No information was inserted into the database.\n")
    else:
        print ("\n")
        print (stats, "new records were inserted into the database from open source lists (Malc0de, Zeus Tracker, Locky and Bambenek).\n")
        
    #cursor = coll.find({})
    #for document in cursor:
    #    pprint(document)

if __name__ == '__main__':
    dbUpdate_opensourcelists()
    