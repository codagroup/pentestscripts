#!/usr/bin/python
import base64
import binascii
import sys

# Convert hashes from ASP.NET Identity v2 to john's format
#
# SELECT CONCAT(UserName, ':', PasswordHash) FROM AspNetUsers
#

with open(sys.argv[1]) as f:
    lines = f.readlines()
lines = [x.strip() for x in lines]


for line in lines:
    user,hashsalt = line.split(":")
    hashbytes = base64.b64decode(hashsalt)
    salt = binascii.hexlify(hashbytes[1:17])
    hash = binascii.hexlify(hashbytes[17:49])
    print(user + ":" + "$pbkdf2-hmac-sha1$1000." + salt + "." + hash)
