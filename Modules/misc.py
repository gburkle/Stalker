'''
Created on Feb 27, 2017

@author: tesoro
'''
import os
#from Database import connections as dbconnect


### Combines intelsource On collection with multiple sources 
def updateIntelsource(intel1, intel2):
    
    first_list = intel1
    second_list = intel2
                
    in_first = set(first_list)
    in_second = set(second_list)
                
    updateintel = in_second - in_first
                
    resultintel = first_list + list(updateintel)

    return (resultintel)


### clear screen
def cls(): 
    #try:
    #    os.system('cls') # For windows
    #except Exception as e: return
    try:
        os.system('clear') # For Linux
    except Exception: return

if __name__ == '__main__':
    pass