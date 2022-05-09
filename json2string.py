# json2string.py - Python script to convert a formatted JSON file into a
#   string with escaped quotes and linefeeds for use in a REST call
#
# Usage: python json2string filename

import sys
import os.path
import json

def usage():
    sys.exit('Usage: python ' + sys.argv[0] + ' filename')

# check for single command argument    
if len(sys.argv) != 2:
    usage()

jsonfile = sys.argv[1]

# check file exists
if os.path.isfile(jsonfile) is False:
    print('File not found: ' + jsonfile)
    usage()

# get a file object and read it in as a string
fileobj = open(jsonfile)
jsonstr = fileobj.read()
fileobj.close()

# do character conversion here
newstr = json.dumps(jsonstr)
## print the converted string
print(newstr)
