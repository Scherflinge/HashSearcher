# This program searches Dropbox for hashes provided, and then returns those that match the hashes
# Author: Eric Scherfling
# Version: 1.0
import dropbox
from dropbox import DropboxOAuth2FlowNoRedirect
from dropbox import Dropbox
from dropbox.files import FolderMetadata
from dropbox.files import FileMetadata
from dropbox.files import FileSharingInfo
import datetime
import pickle
import os


def checkDropBoxHashes(hashes, tokenPath):

    dropBoxToken = None

    # Try to open the token
    if tokenPath and os.path.exists(tokenPath):
        try:
            with open(tokenPath, 'rb') as token:
                dropBoxToken = pickle.load(token)
        except:
            print("File provided was not DropBox credentials")
            return
    else:
        print("DropBox creds not found")
        return

    # These are the tags to search for, the key is what the values 
    # are found under in the responses from Dropbox, the value associated 
    # is a readable vlaue for the JSON file, and for people to read 
    tags = {
        "path_display" : "File Name",
        "originalFilename" : "Original File Name",
        "content_hash" : "SHA256 Hash",
        "owners" : "Owner",
        "client_modified" : "Time Created",
        "sharedWithMeTime" : "Date file was shared",
        "viewedByMeTime" : "Most recent date viewed",
        "lastModifyingUser" : "Last user to modify this file",
        "sharing_info" : "Modified By"
    }

    # Attempt to log in
    dbx = None
    try:
        dbx = dropbox.Dropbox(dropBoxToken)
    except:
        print("Invalid DropBox credentials given")
        return

    # Search the dropbox folders
    a = traverseFolders(dbx, hashesToFind=hashes, tags = tags)
    # Parse the date into a more readable format
    for entry in a:
        entry["Time Created"] = str(entry["Time Created"])+" GMT"
    return a


def traverseFolders(dbx, pth = "", hashesToFind = [], tags = {}):
    toReturn = list()
    # query dropbox for all files and folders in the path provided
    # the path will get deeper and deeper as the algorithm traverses the files
    entries = dbx.files_list_folder(path=pth)

    for entry in entries.entries:
        # check if it is a folder
        if isinstance(entry, FolderMetadata):
            # If a folder is found, traverse into the folder, and attempt to print
            # all values found inside the folder, including other folders
            toReturn.extend(traverseFolders(dbx, pth=entry.path_display,hashesToFind=hashesToFind, tags=tags))
        else:
            # check if the file's hash against our list of hashes
            if hasattr(entry, 'content_hash') and entry.content_hash in hashesToFind:
                di = dict()
                for tag in tags:
                    if hasattr(entry, tag):
                        if tag == "sharing_info" and entry.sharing_info:
                            # Sharing_info has multiple tags beneath it, we only care about one
                            di[tags[tag]] = entry.sharing_info.modified_by
                        else:
                            # Store the values cared about
                            di[tags[tag]] = getattr(entry, tag)
                # Once all tags are gathered from the entry, add it to the list of things found 
                toReturn.append(di)
    # Return a collection of all files of interest found
    # it may be the case that this method is searching deep within a folder
    # once returned to this method, it will be appended to all other files found
    return toReturn
                



def createDropBoxAuth(path):
    APP_KEY = DROPBOX_APPKEY # Removed key access for privacy, you can easily create you own DropBox application file for auth creds.
    APP_SECRET = DROPBOX_APPSECRET

    auth_flow = DropboxOAuth2FlowNoRedirect(APP_KEY, APP_SECRET)

    authorize_url = auth_flow.start()
    print("1. Go to: " + authorize_url)
    print("2. Click \"Allow\" (you might have to log in first).")
    print("3. Copy the authorization code.")
    auth_code = input("Enter the authorization code here: ").strip()

    try:
        oauth_result = auth_flow.finish(auth_code)
    except Exception as e:
        print('Error: %s' % (e,))
        exit(1)

    token = oauth_result.access_token
    try:
        with open(path, 'wb') as filetoken:
            pickle.dump(token, filetoken)
        print("Successfully set up DropBox token!")
    except:
        print("Invalid path")
    return 
