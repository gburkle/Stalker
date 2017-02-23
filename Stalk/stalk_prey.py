'''
Created on Feb 22, 2017

@author: tesoro
'''
import os,re
from Database import connections as dbconnect

def spMenu():
    cls()
    def options():
        print ("""
###### TYPES OF PREY ########
#                           #
#        MD5 Hash           #
#       Domain Name         #
#        IP Address         #
#         email             #
#                           #
#############################

[1] Stalk prey.

[2] Back to main menu. 
""")
    options()
    while True:
        try:
            option = int(input("Option: "))
        except Exception: 
            #print ("Was that even a number? \n")
            option = 0
        if option == 1:
            stalkPrey()
            options()
        elif option == 2:
            break
        else:
            print ("That doesn't seem to be an option. \n")
            options()

def stalkPrey():
    opensourcedb = dbconnect.opensourcelistsColl()
    etpdb = dbconnect.feEtpColl()
    emailPattern = re.compile(r'[^@]+@[^@]+\.[^@]+')
    
    try:
        print ("\n")
        prey = input ("Input Prey: ")
        
        if re.match(emailPattern, prey):
            try:
                if etpdb.find({'from':prey}).count() == 1:
                    #print("Prey is an email address and it's on the database")
                    results = etpdb.find({'from':prey})
                    print ("IntelSource : FireEye ETP")
                    print ("FireETP Alert Number: ", results[0]['alert'])
                    print ("Alert date: ", results[0]['time'])
                    print ("Alert type: ", results[0]['type'])
                    print ("File name or URL: ", results[0]['name'])
                    print ("File Hash:", results[0]['md5'])
                    print ("Sent from: ", results[0]['from'])
                    print ("Sent to: ", results[0]['recipients'])
                    print ("Email Subject: ", results[0]['subject'])
                    print ("Notes or related IoCs: ", str(results[0]['evilips']))
                    
                elif etpdb.find({'from':prey}).count() > 1:
                    print (etpdb.find({'from':prey}).count(), " preys were found!!\n")
                    choise = input ("Do you want to stalk them all? [Y/N]: ")
                    if choise == 'Y' or 'y':
                        results = etpdb.find({'from':prey})
                        for hit in results:
                            print(hit)
                            print("\n")
                    
                        
            except Exception as e: print (e)
        
        
        
        elif opensourcedb.find({'indicator':prey}).count() > 0:
            
            results = opensourcedb.find({'indicator':prey})
            
            print ("Prey found, stalking...\n")
            #print (results[0]['intelsource'])
            if results[0]['intelsource'] == 'FireEye_ETP':
                etpalertnumber = results[0]['notes'][0]['alert']
                results = etpdb.find({'alert':etpalertnumber})
                print ("IntelSource : FireEye ETP")
                print ("FireETP Alert Number: ", results[0]['alert'])
                print ("Alert date: ", results[0]['time'])
                print ("Alert type: ", results[0]['type'])
                print ("File name or URL: ", results[0]['name'])
                print ("File Hash:", results[0]['md5'])
                print ("Sent from: ", results[0]['from'])
                print ("Sent to: ", results[0]['recipients'])
                print ("Email Subject: ", results[0]['subject'])
                print ("Notes or related IoCs: ", str(results[0]['evilips']))
            else:
                #for hit in results:
                #    print(hit)
                print ("IntelSource: ", results[0]['intelsource'])
                print ("Type: ", results[0]['type'])
                print ("Date added to StalkerDB: ", results[0]['date'])
        else:
            print("\n")
            print ("No prey was found\n")

        print ("\n")
        input("Press Enter to Continue...")
        cls()
    except Exception as e: print ("Something is not right with that prey!", e)
    

def cls(): 
    #try:
    #    os.system('cls') # For windows
    #except Exception as e: return
    try:
        os.system('clear') # For Linux
    except Exception: return

if __name__ == '__main__':
    pass
