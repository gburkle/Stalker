from pymongo import MongoClient
import sys

# ======MongoDB connection to intelFeeds Collection================
def opensourcelistsColl():
    try:
        client = MongoClient()
        db = client.StalkerDB
        coll = db.opensourcelists
    except Exception as e: 
        print ("Could not connect to the Stalker Database \"Open Source Feeds Collection\"", e)
        sys.exit(0)
        
    return (coll)
# ================================================================       

# ==========MongoDB connection to fireeyeETP Collection ==========
def feEtpColl():
    try:
        client = MongoClient()
        db = client.StalkerDB
        coll = db.etpalerts
    except Exception as e:
        print ("Could not connect to the Stalker Database \"FireEye ETP Collection:\"", e)
        sys.exit(0)
        
    return (coll)
# ==================================================================
