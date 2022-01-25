#!/usr/bin/env python3
import base64
import re
import sys

# Extract password hashes from a 389-ds database
#
# Dump the database with:
# $ dbscan -f /var/lib/dirsrv/slapd-DIRNAME/db/userRoot/id2entry.db
# Or
# $ ldapsearch -D "cn=Directory Manager" -x -w "Password123" "(userPassword=*)" krbCanonicalName uid cn userPassword ipaNTHash
# And then run this script on the output

next_line = False
user = ''
nt_hash = ''
complete_user = False

if len(sys.argv) != 2:
    print(f"Usage: {sys.argv[0]} <dumpfile>")
    sys.exit(1)

try:
    with open(sys.argv[1]) as f:
        lines = f.readlines()
except FileNotFoundError:
    print(f"File '{sys.argv[1]}' does not exist.")
    sys.exit(1)
except:
    print(f"Usage: {sys.argv[0]} <dumpfile>")
    sys.exit(1)

for line in lines:
    line = line.strip()

    m = re.match('^\s+id [0-9]+$', line)
    if m:
        user = ''
        nt_hash = ''

    # Extract username.
    # Doing this with regex is a bit hacky, but avoids any dependencies outside of stdlib
    m = re.match('(krbCanonicalName|krbPrincipalName): (.*)$', line, re.IGNORECASE)
    if m:
        user = m.group(2)
        encoded_hash = ''
    # Not all account has a proper name, so fall back to UID, and then CN
    if not user:
        m = re.match('^\s*uid: (.*)$', line)
        if m:
            user = m.group(1)
            encoded_hash = ''
        else:
            m = re.match('^\s*cn: (.*)$', line)
            if m:
                user = m.group(1)
                encoded_hash = ''

    # Check if we have an NT hash
    m = re.match('ipaNTHash:: ([a-z0-9\+/=]+)', line, re.IGNORECASE)
    if m:
        nt_hash = '$NT$' + base64.b64decode(m.group(1)).hex()

    # Extract password hash
    m = re.match('userPassword:: ([a-z0-9\+/=]+)', line, re.IGNORECASE)
    if m:
        encoded_hash = m.group(1)
        next_line = True

    # Hash is usually split across multiple lines
    elif next_line == True:
        m = re.match('^\s*([a-z0-9\+/=]+)$', line, re.IGNORECASE)
        if m:
            encoded_hash += m.group(1).strip()
        else:
            next_line = False
            complete_user = True

    if complete_user:
        decoded_hash = base64.b64decode(encoded_hash).decode('utf-8')

        if '{PBKDF2_SHA256}' in decoded_hash:
            binary_hash = base64.b64decode(decoded_hash[15:])
            iterations = int.from_bytes(binary_hash[0:4], byteorder='big')

            # John uses a slightly different base64 encodeding, with + replaced by .
            salt = base64.b64encode(binary_hash[4:68], altchars=b'./').decode('utf-8').rstrip('=')
            # 389-ds specifies an ouput (dkLen) length of 256 bytes, which is longer than John supports
            # However, we can truncate this to 32 bytes and crack those
            b64_hash = base64.b64encode(binary_hash[68:100], altchars=b'./').decode('utf-8').rstrip('=')

            # Formatted for John
            decoded_hash = f"$pbkdf2-sha256${iterations}${salt}${b64_hash}"

        if nt_hash:
            print(f'{user}:{nt_hash}')
        print(f'{user}:{decoded_hash}')
        complete_user = False
        nt_hash = ''
        user = ''
