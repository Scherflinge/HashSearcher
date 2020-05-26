# HashSearcher by Eric Scherfling

HashSearcher is a program written in python that allows a user to search both Google Drive and Dropbox for files from perspective hashes. All files with matching hashes will be returned to the user. This can be done from either a JSON file containing a set of hashes, or from calculating the set of hashes from a folder of files.

Also provided in this submition is log in credentials, allowing you to see the files uploaded to Google Drive, and Dropbox. Provided are the ways to authenticate a user with this program, but for brevity's sake, login tokens have been provided as well. 

## Installation

Use the package manager [pip](https://pip.pypa.io/en/stable/) to install both the [DropBox SDK](https://github.com/dropbox/dropbox-sdk-python) for python.

```bash
pip install dropbox
```

Also install the [Google Drive SDK](https://github.com/gsuitedevs/PyDrive) for python.

```bash
pip install --upgrade google-api-python-client google-auth-httplib2 google-auth-oauthlib
```



## Set Up

I've create test accounts for DropBox and Google Drive found in `ExampleAccounts.txt`.

Create your credentials for DropBox using the `-ds FILEPATH`, `--DropboxSetup FILEPATH` tag. You will be prompted to enter your username and password. `FILEPATH` is the path to where the token will be stored, you will need this later.

```bash
> python3 scherflinge_final.py -ds dropbox.token
"1. Go to: ...
2. Click 'Allow' (you might have to log in first).
3. Copy the authorization code.
Enter the authorization code here:" 
```
The same can be done for Google Drive, using the `-gs FILEPATH` tag.

```bash
> python3 scherflinge_final.py -gs drive.token
"1. Follow the link provided
2. Click your account (or sign in)
3. Click 'Advanced' and then 'Go to HashSearcher'
4. Click 'Allow' to allow the application to view your metadata
5. Click 'Allow' again
Please visit this URL to authorize this application: ..."
```

## Usage

The `-h` tag will show you the parameters available, but a brief rundown will be done here.

To create a file containing hashes, you can use the tag `-hp FOLDERPATH`, `--HashPath FOLDERPATH` to traverse to a folder, and calculate all the hashes. If you wish to save all the hashes that were found, you can use the `-ho OUTPUTFILEPATH`, `--HashOutput OUTPUTFILEPATH` to create a JSON file containing all sha256 and md5 hashes found.

```bash
> python3 scherflinge_final.py -hp images/folder1 -ho hashes.json
``` 

Once the file of hashes is saved, it can be used to query Google Drive and DropBox.

The option to save the hashes can be skipped if instead you want to immediately search Google Drive or DropBox.

To query Google Drive and DropBox, you must supply your tokens and the hashes to search. You can either provide the folder to hash, or a JSON file containing all the hashes you want to search. The hash file can be provided through the `-hf FILEPATH`, `--HashFile FILEPATH` tag, or `-hp FOLDERPATH`, `--HashPath FOLDERPATH` tag. To query DropBox or Google Drive use the `-gt GOOGLETOKEN`, `-dt DROPBOXTOKEN` or `--GoogleToken GOOGLETOKEN`, `-DropboxToken DROPBOXTOKEN`. This will print out all the data found.

```bash
> python3 scherflinge_final.py -hf hashes.json -gt google.token -dt dropbox.token
"Google Drive results:
File Name: 20210305_155203.jpg
Original File Name: 20210305_155203.jpg
MD5 Hash: 9706d464715d003d77b6256f2ecc2225
Owner: ...  

DropBox results:
File Name: ..."
```
You can substitute `-hf FILEPATH` for `-hp FOLDERPATH` if you want to check in the hashes of a folder against Google Drive or DropBox in real time.

You also have the option to check only Google Drive or Dropbox by omitting whichever token you don't want to query.

You may also want to store your results, this can be done with the `-o OUTPUTFILE`, `--Output OUTPUTFILE` tag. This allows you to save your search results into a json file.
```bash
> python3 scherflinge_final.py -hf hashes.json -gt google.token -dt dropbox.token -o output.json
```
