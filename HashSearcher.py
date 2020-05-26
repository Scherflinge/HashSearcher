# This program searches Google Drive and DropBox to find files matching the hashes provided
# Author: Eric Scherfling
# Version: 1.0 
import googledrive_seacher
import dropbox_searcher
import argparse
import os
import hashlib
import json

def main():
    parser = argparse.ArgumentParser()
    search = parser.add_argument_group("Parse Parameters")
    searchhash = search.add_mutually_exclusive_group()
    searchhash.add_argument("-hf", "--HashFile", dest="hashfile", type=str, help="Path to the file of hashes to search", required=False)
    searchhash.add_argument("-hp", "--HashPath", dest="hashpath", type=str, help="Path to the folder of hashes to search", required=False)
    search.add_argument("-ho", "--HashOutput", dest="hashoutput", type=str, help="Path to where to save the hashes of the folder", required=False)
    search.add_argument("-o", "--Output", dest="output", type=str, help="Path of the directory to save the output", default=None, required=False)
    search.add_argument("-gt", "--GoogleToken", dest="googletoken", type=str,required=False, help="Path to the file of Google credentials", default=None)
    search.add_argument("-dt", "--DropboxToken", dest="dropboxtoken", type=str, required=False, help="Path to the file of DropBox credentials", default=None)

    setup = parser.add_mutually_exclusive_group()
    setup.add_argument("-gs", "--GoogleSetup", dest="newgoogletoken", type=str, required=False, help="Run set up for a Google Drive token, path for where to store credentials", default=None)
    setup.add_argument("-ds", "--DropboxSetup", dest="newdropboxtoken", type=str, required=False, help="Run set up for a DropBox token, path for where to store credentials", default=None)

    args = parser.parse_args()
    
    if args.newgoogletoken:
        # Check if a google token has to be set up
        print(args.newgoogletoken)
        googledrive_seacher.createGoogleAuth(args.newgoogletoken)
    elif args.newdropboxtoken:
        # Check if a dropbox token has to be set up
        print(args.newdropboxtoken)
        dropbox_searcher.createDropBoxAuth(args.newdropboxtoken)
    else:
        # Start searching through drive and dropbox
        results = dict()
        hashfile = args.hashfile
        hashpath = args.hashpath
        
        # If no source of hashes were provided, exit
        if not hashfile and not hashpath:
            print("No source of hashes provided")
            parser.print_help()
            return

        googletoken = args.googletoken
        dropboxtoken = args.dropboxtoken
        hashoutput = args.hashoutput

        # If a folder was supplied, but no output source was supplied, 
        # or if no token to search was supplied, then exit.
        if (hashpath and not (googletoken or dropboxtoken) and not hashoutput):
            print("No credentials provided / No output path for hashing files")
            parser.print_help()
            return

        # The difference between the check above and below is this behavior:
        # There's no need to parse a file if no token is supplied,
        # but if there's a folder supplied, you may want to save the hashes without searching.
        # There's no need to copy a file you already have by parsing it and then writing it again.

        # If the hashfile was supplied, but no token to search was supplied, 
        # then exit.
        if (hashfile and not (googletoken or dropboxtoken)):
            print("No credentials provided with hash file")
            parser.print_help()
            return
        
        # Parse the hashes either by file or calculating it in real time
        hashes = {}
        if hashfile:
            hashes = parseFile(hashfile)
        elif hashpath:
            hashes = parseFolder(hashpath)

        # check hashes actually exist
        if len(hashes) == 0:
            print("Hashes not found")
            return

        # If the hashes should be saved, first do a check to make sure you aren't reading 
        # from a file, only write if you computed them in real time
        if hashoutput and not hashfile:
            with open(hashoutput, 'w') as hashoutputfile:
                hashoutputfile.write(json.dumps(hashes))
            # If we are only calculating then saving our hashes, we can exit now
            if not (googletoken or dropboxtoken):
                return

        # Search Google
        if googletoken and "md5" in hashes:
            googleresults = googledrive_seacher.checkGoogleHashes(hashes["md5"], googletoken)
            # If there were any results from the google search, don't return any
            if googleresults and len(googleresults) > 0:
                results["Google Drive"] = googleresults
        #Search DropBox
        if dropboxtoken and "sha256" in hashes:
            dropboxresults = dropbox_searcher.checkDropBoxHashes(hashes["sha256"], dropboxtoken)
            # If there were any results from the dropbox search, don't return any
            if dropboxresults and len(dropboxresults) > 0:
                results["DropBox"] = dropboxresults

        output = args.output

        # If the user wants to store the final result, write it to the file supplied 
        if output:
            with open(output,'w') as outputf:
                jsonobj = json.dumps(results)
                outputf.write(jsonobj)
        # Otherwise, just print out the results
        else:
            if "DropBox" in results:
                print("DropBox results:")
                for dbresult in results["DropBox"]:
                    for tag in dbresult:
                        #print tag by tag
                        print("{0}: {1}".format(tag, dbresult[tag]))
                    # print an extra line at the end of each file, to make it easier to read
                    print()
            if "Google Drive" in results:
                print("Google Drive results:")
                for dbresult in results["Google Drive"]:
                    for tag in dbresult:
                        #print tag by tag
                        print("{0}: {1}".format(tag, dbresult[tag]))
                    # print an extra line at the end of each file, to make it easier to read
                    print()
                    

def parseFile(filepath):
    hashes = {}
    # Use JSON to parse the file, if there's an error, send back an empty dictionary
    # The JSON files are keyed by hash name, (sha256, md5) and the value is a list of hashes
    try:
        with open(filepath, 'rb') as hashFile:
            hashes = json.loads(hashFile.read())
        if not ("md5" in hashes and "sha256" in hashes):
            return {}
        return hashes
    except:
        return hashes


def parseFolder(folderPath):
    md5hashes = []
    sha256hashes = []
    # Traverse all files in a directory
    for dirName, _, fileList in os.walk(folderPath):
        for fname in fileList:
            fullpath = os.path.join(dirName, fname)
            # Each file's hash is then calculated in md5 and sha256
            md5hashes.append(computemd5Hash(fullpath))
            # DropBox uses it's own method of computing the sha256 hash
            # based solely on metadata, so we have to use their hashing
            # method.
            sha256hashes.append(compute_dropbox_hash(fullpath))
    if len(sha256hashes) == 0 and len(md5hashes) == 0:
        # if there were files to hash in that directory, send an empty dictionary
        return {}
    return {"md5": md5hashes, "sha256": sha256hashes}


def computesha256Hash(filename):
    sha256_hash = hashlib.sha256()
    with open(filename, "rb") as f:
        # Read and update hash string value in blocks of 4K
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()


def computemd5Hash(filename):
    md5_hash = hashlib.md5()
    with open(filename, "rb") as f:
        # Read and update hash string value in blocks of 4K
        for byte_block in iter(lambda: f.read(4096), b""):
            md5_hash.update(byte_block)
        return md5_hash.hexdigest()

def compute_dropbox_hash(filename):
    with open(filename, 'rb') as f:
        block_hashes = b''
        while True:
            chunk = f.read(4*1024*1024)
            if not chunk:
                break
            block_hashes += hashlib.sha256(chunk).digest()
        return hashlib.sha256(block_hashes).hexdigest()


if(__name__ == "__main__"):
    main()
