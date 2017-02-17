'''
Created on Feb 16, 2017

@author: tesoro
'''
import sys, os
import json
from  Intel_Feeds import open_source_lists as feeds
from pymongo import MongoClient

try:
    client = MongoClient()
    db = client.intelFeeds
except Exception as e: print ("Could not connect to the Database", e)

def dbCreate():
    
    
    coll = db.opensourcelists
    
    print ("Downloading and importing information from open source lists ...", end="")
    try:
        
        for key, value in feeds.fetch_feeds().items():
            #print ('IP = ', key)
            #print ('Intel = ', value)
            try:
                post = {key:value}
                coll.insert(post, check_keys=False).inserted_id
            except Exception as e: print(key, " could not be inserted into the database!!", e)
                      
    except Exception as e: print("Could not update database with Open Source Lists information", e)
    print ("[DONE]")

if __name__ == '__main__':
    dbCreate()
    