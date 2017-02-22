'''
Created on Feb 16, 2017

@author: tesoro
'''
import os
import datetime
from  Intel_Feeds import open_source_lists as feeds
from Intel_Feeds import fireeye_export_list as fireeye
from Database import connections as dbconnect
from Database import statistics as stats

def dbMenu():
    
    def options():
        print ("""
 ____ ____ ____ ____ ____ ____ ____ ____ ____ 
||D |||a |||t |||a |||b |||a |||s |||e |||. ||
||__|||__|||__|||__|||__|||__|||__|||__|||__||
|/__\|/__\|/__\|/__\|/__\|/__\|/__\|/__\|/__\|

[1] Update Open Source Feeds.
[2] Update FireEye ETP.
[3] Statistics.

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
            stats.dbStatistics()
            options()
        elif option == 4:
            break
        else:
            print ("That doesn't seem to be an option. \n")
            options()
            

# ================================================================================================================================================
# Update MongoDB Database "StalkerDB", Collection "opensourcelists" with information from Malc0de, Zeus Tracker, Locky and Bambenek

def dbUpdate_opensourcelists():
    
    stats = 0
    coll =  dbconnect.opensourcelistsColl() 
    
    
    
    print ("Downloading and inserting into the database information from open source lists (Malc0de, Zeus Tracker, Locky, Bambenek and Emerging Threats) ...\n")
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
        print (stats, "new records were inserted into the database from open source lists (Malc0de, Zeus Tracker, Locky, Bambenek and Emerging Threats).\n")
        
    
#=============================================================================================================================================================
# Read FireEye ETP CSV alerts file with structure:
# Alert ID,Message ID,Date & Time,From,Recipients,Subject,Malware Type,Malware File Type,Malware Name,Malware MD5,Malware Analysis Application,\
# Malware Analysis OS,Virus Total,Source IP,Source Country,Malware Comunication IP,Malware Communication Countries,Email Status,Threat Type,Risk Level
#
# This creates a new collection on StalkerDB called "etpalerts" and puts all FiereEye ETP information on it.
# It then opens StalkerDB "opensourcelists" collection and updates the collection with IOCs from the file. 
# It uses "Intel_Feeds\fireeye_export_list.py" to generate the dictionary list used to update databases. 

## Dictionary name: etpalerts.
## Key = ETP Alert number
## Value = { Time, From, Recipients, Subject, Type, Name "name of the binary file, or full URL", MD5, evilips[] }

def dbUpdate_FireeyeETP():
    
    coll = dbconnect.feEtpColl() # Connects to StalkerDB.etpalerts
    coll2 = dbconnect.opensourcelistsColl() # Connect to StalkerDB.opensourcelists
    
    today = datetime.datetime.now().strftime("%m-%d-%Y")
    stats = 0
    file = input("Enter the name of the file containing ETP alerts in CSV form. (Include absolute path if file is not in Stalker folder): ")
    
    if os.path.exists(file):
        
        etpalerts = fireeye.readETP(file)
        try:
            print("\n")
            print("Updating StalkerDB.etpalerts Collection....")        
            for key, value in etpalerts.items():
                if coll.find({'alert': key}).count() > 0:
                    # Value already in database
                    pass
                else:
                    data = {'alert': key, 'time': value['Time'], 'dbtime': today, 'from': value['From'], 'recipients':value['Recipients'], 'subject':value['Subject'], 'type':value['Type'], 'name':value['Name'], 'md5':value['MD5'], 'evilips':value['evilips']}
                    coll.insert(data)
                    stats += 1
                    
        except Exception as e: 
            print ("Something went wrong while updating \"etpalerts\" collection!", e) 
           
        
        if stats == 0:
            print ("\n")
            print ("Nothing new found. No information was inserted into the database. ¯\_(ツ)_/¯ \n")
        else:
            print ("\n")
            print (stats, "new records were inserted into the database from the FireEye ETP alerts file.\n")
            
## End of importing data from alerts file into FireETP database.
## Next we will use the same information to update Intel Feeds database with ETP information.             

## Key = ETP Alert number
## Value = { Time, From, Recipients, Subject, Type, Name "name of the binary file, or full URL", MD5, evilips[] }

## Now using coll2 to connect to opensourcelists collection on StalkerDB

            
        try:
            print("\n")
            print("Updating StalkerDB.opensourcelists with ETP information.....")
            statshash = 0
            statsurls = 0
            statsunknown = 0
            
            for key, value in etpalerts.items():
                if  value['Type'] == 'url':
                    if coll2.find({'indicator':value['Name']}).count() > 0:
                        pass
                        # Value already in database
                    else:
                        # URL path comes as evilips for URLS from fireeye_export_list.py, key is teh ETP alert number
                        data = {'indicator':value['Name'], 'type':'Intel::DOMAIN', 'intelsource':'FireEye_ETP', 'date':today, 'notes':[key, value['evilips']]}
                        coll2.insert(data) #### Insert into the database
                        statsurls += 1
                        
                              
                elif value['MD5'] !=  'N/A':
                    if coll2.find({'indicator': value['MD5']}).count() > 0:
                        pass
                        # Value already in database
                    else:
                        # Key is the ETP alert number, Name is the file name, evilips is the IP addresses associated with the binary
                        data = {'indicator': value['MD5'], 'type': 'Intel::FILE_HASH', 'intelsource': 'FireEye_ETP', 'date':today, 'notes':[key, value['Name'], value['evilips']]}
                        coll2.insert(data) ### Insert into the database
                        statshash += 1
                        
                else:
                    statsunknown += 1
            
        except Exception as e: 
            print ("Something went wrong while updating StalkerDb.opensourcelists collection with ETP information.", e)  
        
        if stats == 0:
            print ("\n")
            print ("Nothing new found. No information was inserted into the database. ¯\_(ツ)_/¯ \n")
        elif statsunknown > 0:
            print ("\n")
            print ("%d New URLs, and %d new Hashes were inserted into the Intel Feeds database from the FireEye ETP alerts file.\n" % (statsurls, statshash))
            print (statsunknown, " unknown records were ignored! ¬_¬ ")
        else:
            print ("\n")
            print ("%d New URLs, and %d new Hashes were inserted into the Intel Feeds database from the FireEye ETP alerts file.\n" % (statsurls, statshash))    
             
    else: # End of "if os.path.exists"
        print ("File not found. Make sure the file is on the Stalker folder, or use absolute path.\n")
     
    

# ================================================================================================================================================================
if __name__ == '__main__':
    dbMenu()
    