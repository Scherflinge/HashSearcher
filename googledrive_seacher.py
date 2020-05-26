# This program searches Google Drive for hashes provided, and then returns those that match the hashes
# Author: Eric Scherfling
# Version: 1.0
from __future__ import print_function
import pickle
import os.path
from googleapiclient.discovery import build
from google_auth_oauthlib.flow import InstalledAppFlow
from google.auth.transport.requests import Request
import json

def checkGoogleHashes(hashesToCheck, tokenPath):
        
    creds = None
    
    # Try to open the token
    if tokenPath and os.path.exists(tokenPath):
        try:
            with open(tokenPath, 'rb') as token:
                creds = pickle.load(token)
        except:
            print("File provided was not Google Drive credentials")
            return

    if not creds:
        print("Google Drive creds not found")
        return

    # If the credentials are no longer valid, refresh them
    try:
        if not creds.valid:
            if creds and creds.expired and creds.refresh_token:
                creds.refresh(Request())
            
            # Save the credentials for the next run
            with open(tokenPath, 'wb') as token:
                pickle.dump(creds, token)
    except:
        print("Invalid Google Drive credentials given")
        return

    service = build('drive', 'v3', credentials=creds)
    
    # These are the tags to search for, the key is what the values 
    # are found under in the responses from Dropbox, the value associated 
    # is a readable vlaue for the JSON file, and for people to read 
    tags = {
        "name" : "File Name",
        "originalFilename" : "Original File Name",
        "md5Checksum" : "MD5 Hash",
        "owners" : "Owner",
        "createdTime" : "Time Created",
        "sharedWithMeTime" : "Date file was shared",
        "viewedByMeTime" : "Most recent date viewed",
        "lastModifyingUser" : "Last user to modify this file"
    }

    # To create the request, we can push together all the tags we're searching
    # for and create a request string
    searchTags = "nextPageToken, files(" 
    for tag in tags.keys():
        searchTags+=tag+", "
    # get rid of the last comma and space
    searchTags = searchTags[0:len(searchTags)-2]
    searchTags+=")"

    # Call the Drive v3 API
    results = service.files().list(fields=searchTags).execute()
    items = results.get('files', [])

    foundFiles = list()

    if not items:
        return []
    else:
        for item in items:
            # check file's hash against the hashes we're searching for
            if "md5Checksum" in item and item["md5Checksum"] in hashesToCheck:
                validFile = dict()
                #store all tags we want
                for tag in tags:
                    if tag in item:
                        if tag == "owners":
                            # The 'owners' tag relays a list of owners
                            listOfOwners = list()
                            for ownerdetails in item[tag]:
                                # We just want the names of the owners, iterate over them
                                # add them to the list of owners 
                                listOfOwners.append(ownerdetails["emailAddress"])
                            validFile[tags[tag]] = listOfOwners        
                        elif tag == "lastModifyingUser":
                            # All we care about from 'lastModifyingUser' is the email address associated with it
                            validFile[tags[tag]] = item[tag]["emailAddress"]
                        else:
                            # Add to the list of tags
                            validFile[tags[tag]] = item[tag]
                # Add file to list of files
                foundFiles.append(validFile)
    # Send back all found files
    return foundFiles

def createGoogleAuth(picklecredsPath):
    auth_path = None # Removed key access for privacy, you can easily create you own google application file for auth creds.
    print("1. Follow the link provided")
    print("2. Click your account (or sign in)")
    print("3. Click \'Advanced\' and then \'Go to Quickstart\'")
    print("4. Click \'Allow\' to allow the application to view your metadata")
    print("5. Click \'Allow\' again")
    try:
        flow = InstalledAppFlow.from_client_config(auth_path, ['https://www.googleapis.com/auth/drive.metadata.readonly'])
        creds = flow.run_local_server(port=0)
            
        with open(picklecredsPath, 'wb') as token:
            pickle.dump(creds, token)
    
        print("Successfully set up Google Drive token!")
    except:
        print("Invalid path")
        return
