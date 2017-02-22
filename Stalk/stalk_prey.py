'''
Created on Feb 22, 2017

@author: tesoro
'''
import os
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
    #etpdb = dbconnect.feEtpColl()
    
    try:
        prey = input ("Prey: ")
        results = opensourcedb.find({'indicator':prey})
        for hit in results:
            print(hit)
        print ("\n")
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