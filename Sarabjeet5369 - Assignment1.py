'''Copyright (c) 2015 HG,DL,UTA
   Python program runs on local host, uploads, downloads, encrypts local files to google.
   Please use python 2.7.X, pycrypto 2.6.1 and Google Cloud python module '''

'''
Name: Sarabjeet Singh
Course Number: CSE6331-001
Lab Number: Assignment-1
Time: 06:00 PM - 07:50 PM

** check comments at the end of this page. **
'''

#import statements.
import argparse
import httplib2
import os
import sys
import json
import time
import datetime
import io
import hashlib
#Google apliclient (Google App Engine specific) libraries.
from apiclient import discovery
from oauth2client import file
from oauth2client import client
from oauth2client import tools
from apiclient.http import MediaIoBaseDownload
#pycry#pto libraries.
from Crypto import Random
from Crypto.Cipher import AES


# Encryption using AES
#You can read more about this in the following link
#http://eli.thegreenplace.net/2010/06/25/aes-encryption-of-files-in-python-with-pycrypto


#Initial password to create a key
password = '  '
#key to use
#key = hashlib.sha256(password).digest()

#this implementation of AES works on blocks of "text", put "0"s at the end if too small.
def pad(s):
    return s + b"\0" * (AES.block_size - len(s) % AES.block_size)

#Function to encrypt the message
def encrypt(message, key, key_size=256):
    message = pad(message)
    key = hashlib.sha256(password).digest()
    #iv is the initialization vector
    iv = Random.new().read(AES.block_size)
    #encrypt entire message
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return iv + cipher.encrypt(message)

#Function to decrypt the message
def decrypt(ciphertext, key):
    iv = ciphertext[:AES.block_size]
    key = hashlib.sha256(password).digest()
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = cipher.decrypt(ciphertext[AES.block_size:])
    return plaintext.rstrip(b"\0")

#Function to encrypt a given file
def encrypt_file(file_name, key):
    #Open file to read content in the file, encrypt the file data and
    #create a new file and then write the encrypted data to it, return the encrypted file name.
     
    with open(file_name, 'rb') as f:            # reads the content in binary; See REFERENCES[1]
        normal_text = f.read()                  
    enc = encrypt( normal_text, key)            # the content obtained henceforth would be treated as "message"
    with open("enc_"+file_name, "wb") as f:     # append the file with .enc; implying the file is encrypted
        f.write(enc)                            # cipher the file
    os.remove(file_name)

#Function to decrypt a given file.
def decrypt_file(file_name, key):
    #open file read the data of the file, decrypt the file data and 
    #create a new file and then write the decrypted data to the file.
    with open(file_name, 'rb') as f:            # read the file as binary
        cipher_text = f.read()                  
    dec = decrypt(cipher_text, key)             # treat the binary content as "message"
    with open(file_name[:-4], 'wb') as f:       # open the file and exclude the .enc extension from the file_name
        f.write(dec)                            # write the deciphered text



_BUCKET_NAME = 'bucket1sjeet' #name of your google bucket.
_API_VERSION = 'v1'

# Parser for command-line arguments.
parser = argparse.ArgumentParser(
    description=__doc__,
    formatter_class=argparse.RawDescriptionHelpFormatter,
    parents=[tools.argparser])


# client_secret.json is the JSON file that contains the client ID and Secret.
#You can download the json file from your google cloud console.
CLIENT_SECRETS = os.path.join(os.path.dirname(__file__), 'client_secret.json')

# Set up a Flow object to be used for authentication.
# Add one or more of the following scopes. 
# These scopes are used to restrict the user to only specified permissions (in this case only to devstorage) 
FLOW = client.flow_from_clientsecrets(CLIENT_SECRETS,
  scope=[
      'https://www.googleapis.com/auth/devstorage.full_control',
      'https://www.googleapis.com/auth/devstorage.read_only',
      'https://www.googleapis.com/auth/devstorage.read_write',
    ],
    message=tools.message_if_missing(CLIENT_SECRETS))

#Downloads the specified object from the given bucket and deletes it from the bucket.
def get(service):    
  #User can be prompted to input file name(using raw_input) that needs to be be downloaded, 
  #as an example file name is hardcoded for this function.
  get_file = raw_input ("Enter a file name: ")
  decrypt_key_file = raw_input ("\nEnter key to decrypt the file: ") 
  try:
# Get Metadata
    req = service.objects().get(
        bucket=_BUCKET_NAME,
        object=get_file,
        fields='bucket,name,metadata(my-key)',    
        )                   
    resp = req.execute()
    print json.dumps(resp, indent=2)

# Get Payload Data
    req = service.objects().get_media(
            bucket=_BUCKET_NAME ,
            object=get_file,
        )    
# The BytesIO object may be replaced with any io.Base instance.
    fh = io.BytesIO()
    downloader = MediaIoBaseDownload(fh, req, chunksize=1024*1024) #show progress at download
    done = False
    while not done:
        status, done = downloader.next_chunk()
        if status:
            print "Download %d%%." % int(status.progress() * 100)
        print 'Download Complete!'
        dec = decrypt(fh.getvalue(), decrypt_key_file)
    with open("Images/"+get_file, 'wb') as fo:
        fo.write(dec)
        print json.dumps(resp, indent=2)    

  except client.AccessTokenRefreshError:
    print ("Error in the credentials")

    #Puts a object into file after encryption and deletes the object from the local PC.
def put(service):                                # REFERENCES[2]
    '''User inputs the file name that needs to be uploaded.
       Encrypt the given file using AES encryption 
       and then upload the file to your bucket on the google cloud storage.
       Remove the file from your local machine after the upload. '''
          # The BytesIO object may be replaced with any io.Base instance.
    #media = MediaIoBaseUpload(io.BytesIO('some data'), 'text/plain')
        # All object_resource fields here are optional.
    name_file = raw_input("Enter the file name: ")
    key_file = raw_input("Enter the key for the given file: ")

    start = time.time()

    enc = encrypt_file(name_file, key_file)      # The encrypted file is returned from encrypt()
    

    object_resource = {
                'metadata': {'my-key': 'my-value'},
                'contentLanguage': 'en',
                'md5Hash': 'HlAhCgICSX+3m8OLat5sNA==',
                'crc32c': 'rPZE1w==',
                        }
    req = service.objects().insert(
                bucket=_BUCKET_NAME,
                name=name_file,
                #body=object_resource,     # optional
                media_body=enc)

    resp = req.execute()

    print json.dumps(resp, indent=2)


#Lists all the objects from the given bucket name
def listobj(service):                                 # REFERENCES[3]
    '''List all the objects that are present inside the bucket. '''
    fields_to_return = 'nextPageToken,items(bucket,name,metadata(my-key))'
    req = service.objects().list(
            bucket = _BUCKET_NAME)
            #fields=fields_to_return,    # optional
            #maxResults=42)              # optional

        # If you have too many items to list in one request, list_next() will
        # automatically handle paging with the pageToken.
    while req is not None:
        resp = req.execute()
        data = json.loads(json.dumps(resp, indent=2))   # converts the json response to Python dictionary format
        for i in range(len(data['items'])):
            print data['items'][i]['name']
        req = service.objects().list_next(req, resp)


#This deletes the object from the bucket
def deleteobj(service):                               # REFERENCES[4]
    '''Prompt the user to enter the name of the object to be deleted from your bucket.
        Pass the object name to the delete() method to remove the object from your bucket'''
    del_obj = raw_input("Please enter the name of the object to be deleted")

    service.objects().delete(
        bucket = _BUCKET_NAME,
        object = del_obj
        ).execute() 

    
def main(argv):
  # Parse the command-line flags.
  flags = parser.parse_args(argv[1:])
  
  #sample.dat file stores the short lived access tokens, which your application requests user data, attaching the access token to the request.
  #so that user need not validate through the browser everytime. This is optional. If the credentials don't exist 
  #or are invalid run through the native client flow. The Storage object will ensure that if successful the good
  # credentials will get written back to the file (sample.dat in this case). 
  storage = file.Storage('sample.dat')
  credentials = storage.get()
  if credentials is None or credentials.invalid:
    credentials = tools.run_flow(FLOW, storage, flags)

  # Create an httplib2.Http object to handle our HTTP requests and authorize it
  # with our good Credentials.
  http = httplib2.Http()
  http = credentials.authorize(http)

  # Construct the service object for the interacting with the Cloud Storage API.
  service = discovery.build('storage', _API_VERSION, http=http)

  #This is kind of switch equivalent in C or Java.
  #Store the option and name of the function as the key value pair in the dictionary.
  options = {1: put, 2: get, 3:listobj, 4:deleteobj}
  
  option = int(raw_input("Please enter an option: \n1. PUT an Object.\n2. GET an Object.\n3. LIST Objects.\n4. DELETE Objects.\n"))  #Take the input from the user to perform the required operation
  #print "Option selected: %d", option 
  #for example if user gives the option 1, then it executes the below line as put(service) which calls the put function defined above.
  options[option](service)


if __name__ == '__main__':
    main(sys.argv)
# [END all]

'''
REFERENCES:

1. http://stackoverflow.com/questions/1035340/reading-binary-file-in-python

2. https://cloud.google.com/storage/docs/json_api/v1/objects/insert

3. https://cloud.google.com/storage/docs/json_api/v1/objects/list

4. https://cloud.google.com/storage/docs/json_api/v1/objects/delete

COMMENTS:

* Didn't comment the json.dumps on line 181 because presence of the response would imply the successfull upload of the file.
* The Images folder in present is the folder where the decrypted files downloaded from the cloud are present. I'm sending empty fodler so that you can decrypt the files and see them present there.


'''
