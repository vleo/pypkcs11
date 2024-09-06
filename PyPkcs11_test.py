#!/usr/bin/python3.11

from PyPkcs11 import dumpBuf

from PyPkcs11 import Pkcs11Connection
from uuid import uuid4

conn = Pkcs11Connection("/opt/aktivco/rutokenecp/x86_64/librtpkcs11ecp.so")

conn.fill_slots_list()

print("Slots list:\n", "\n".join([str(v) for v in conn.slots]))

if len(conn.slots) == 0:
    quit(1)

#conn.fill_mechanism_list()
#print("Slots list:\n", "\n".join([str(v) for v in conn.slots]))
#conn.format_token(0, "87654321", "12345678", "myVlRutoken")

if len(conn.slots) == 0:
    quit(2)

conn.open_sessions()

conn.login(0, "12345678")

if False:
    u4 = uuid4()
    conn.gen_key_symm_kuznechik(0, str(u4))
    encKeysCnt, encKeysUIP = conn.findKuznechikSecretKey(0, str(u4))
else:
    u4str = '3d1eb7dd-e4d7-4d5b-9c3e-fc6d6b1e6c68'

encKeysCnt, encKeysUIP = conn.findKuznechikSecretKey(0, u4str)

print(f"encKeysCnt = {encKeysCnt:d} encKeysPtr = {encKeysUIP:d}")

if False:
    plainTextStr = "OivEd+grojdyxEm0"

    encryptedSize, encrypted, encryptedBytes = conn.encryptKuznechik(0, encKeysCnt, encKeysUIP, plainTextStr)
    print(f"encryptedSize = {encryptedSize:d} encrypted = {encrypted:d} encryptedBytes hex = {encryptedBytes.hex(' ')}")
    #dumpBuf(encrypted, encryptedSize)

    with open("valutkey.crypto.bin", "wb") as f:
        f.write(encryptedBytes)

with open("valutkey.crypto.bin", "rb") as f:
    encryptedBytesRead = f.read(16)

plainTextSize, decrypted, decryptedStr = conn.decryptKuznechik(0, encKeysCnt, encKeysUIP, encryptedBytesRead)
print(f"plainTextSize = {plainTextSize:d} decrypted = {decrypted:d} decryptedStr = {decryptedStr:s}")

from subprocess import run, Popen
from os import environ


osslRun = run(['openssl',
               'aes-256-cbc',
               '-d',
               '-a',
               '-salt',
               '-pbkdf2',
               '-pass',
               'env:OSSLVAULTPASS',
               '-in',
               'passwords.yaml.vault'])

conn.free_pkcs11()
