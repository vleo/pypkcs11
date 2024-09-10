#!/usr/bin/python3.11

from PyPkcs11 import dumpBuf, Pkcs11Exception
import argparse

from PyPkcs11 import Pkcs11Connection
from uuid import uuid4

from subprocess import CompletedProcess, run, Popen, PIPE
import os

ap: argparse.ArgumentParser = argparse.ArgumentParser()
ap.add_argument("--inittoken", action="store_true")
ap.add_argument("--sopin", action="store")
ap.add_argument("--pin", action="store")

ap.add_argument("--createvaultsecret", action="store")
ap.add_argument("--keyid", action="store")

ap.add_argument("--getvaultsecret", action="store_true")

ap.add_argument("--createsslpwdsvault", action="store_true")
ap.add_argument("--promkey", action="store")
ap.add_argument("--testkey", action="store")
ap.add_argument("--subkey", action="store")

cmdLineArgs: argparse.Namespace = ap.parse_args()

conn = Pkcs11Connection("/opt/aktivco/rutokenecp/x86_64/librtpkcs11ecp.so")

conn.fill_slots_list()

print("Slots list:\n", "\n".join([str(v) for v in conn.slots]))

if len(conn.slots) == 0:
    quit(1)

#conn.fill_mechanism_list()
#print("Slots list:\n", "\n".join([str(v) for v in conn.slots]))
if cmdLineArgs.inittoken:
    if not (cmdLineArgs.sopin and cmdLineArgs.pin):
        raise Pkcs11Exception(f"Must specify --sopin and --pin for --inittoken")
    sopin = cmdLineArgs.sopin
    pin = cmdLineArgs.pin
    conn.format_token(0, sopin, pin, "RootCARutoken")
    conn.open_sessions()
    conn.login(0, pin)
    u4 = uuid4()
    conn.gen_key_symm_kuznechik(0, str(u4))
    print(f"Created secret key for kuznechik with id= {str(u4)}")

if cmdLineArgs.createvaultsecret:
    # ./PyPkcs11_test.py --createvaultsecret $(apg -MCLSN -m16 -n1) --pin 662607 --keyid 33b22a65-68de-4841-880c-bc93417a0337
    if not (cmdLineArgs.keyid and cmdLineArgs.pin):
        raise Pkcs11Exception(f"Must specify --keyid and --pin for --createvaultsecret")
    conn.open_sessions()
    conn.login(0, cmdLineArgs.pin)

    u4str = cmdLineArgs.keyid
    plainTextStr = cmdLineArgs.createvaultsecret

    encKeysCnt, encKeysUIP = conn.findKuznechikSecretKey(0, str(u4str))
    print(f"encKeysCnt = {encKeysCnt:d} encKeysPtr = {encKeysUIP:d}")

    encryptedSize, encrypted, encryptedBytes = conn.encryptKuznechik(0, encKeysCnt, encKeysUIP, plainTextStr)
    print(f"encryptedSize = {encryptedSize:d} encrypted = {encrypted:d} encryptedBytes hex = {encryptedBytes.hex(' ')}")
    #dumpBuf(encrypted, encryptedSize)

    with open("valutkey.crypto.bin", "wb") as f:
        f.write(encryptedBytes)

if cmdLineArgs.getvaultsecret:
    if not (cmdLineArgs.keyid and cmdLineArgs.pin):
        raise Pkcs11Exception(f"Must specify --keyid and --pin for --getvaultsecret")
    conn.open_sessions()
    conn.login(0, cmdLineArgs.pin)
    with open("valutkey.crypto.bin", "rb") as f:
        encryptedBytesRead = f.read(16)

    u4str = cmdLineArgs.keyid
    encKeysCnt, encKeysUIP = conn.findKuznechikSecretKey(0, u4str)
    print(f"encKeysCnt = {encKeysCnt:d} encKeysPtr = {encKeysUIP:d}")
    plainTextSize, decrypted, decryptedStr = conn.decryptKuznechik(0, encKeysCnt, encKeysUIP, encryptedBytesRead)
    print(f"plainTextSize = {plainTextSize:d} decrypted = {decrypted:d} decryptedStr = {decryptedStr:s}")

if cmdLineArgs.createsslpwdsvault:
    if not (cmdLineArgs.keyid and cmdLineArgs.pin):
        raise Pkcs11Exception(f"Must specify --keyid and --pin for --createsslpwdsvault")
    if not (cmdLineArgs.promkey and cmdLineArgs.testkey and cmdLineArgs.subkey):
        raise Pkcs11Exception(f"Must specify --promkey, --testkey and --subkey for --createsslpwdsvault")
    conn.open_sessions()
    conn.login(0, cmdLineArgs.pin)
    with open("valutkey.crypto.bin", "rb") as f:
        encryptedBytesRead = f.read(16)
    u4str = cmdLineArgs.keyid
    encKeysCnt, encKeysUIP = conn.findKuznechikSecretKey(0, u4str)
    print(f"encKeysCnt = {encKeysCnt:d} encKeysPtr = {encKeysUIP:d}")
    plainTextSize, decrypted, osslVaultPass = conn.decryptKuznechik(0, encKeysCnt, encKeysUIP, encryptedBytesRead)
    # print(f"plainTextSize = {plainTextSize:d} decrypted = {decrypted:d} osslVaultPass = {osslVaultPass:s}")

    sslpwds = f"""prom_pwd: {cmdLineArgs.promkey}
test_pwd: {cmdLineArgs.testkey}
subca_pwd: {cmdLineArgs.subkey}
"""

    sslpwdsb = sslpwds.encode("utf-8")

    osslPopen = Popen(['openssl',
                       'aes-256-cbc',
                       '-a',
                       '-salt',
                       '-pbkdf2',
                       '-pass',
                       'env:OSSLVAULTPASS',
                       '-out',
                       'passwords.yaml.vault'
                       ],
                      env=dict(os.environ, OSSLVAULTPASS=osslVaultPass),
                      stdin=PIPE,
                      stdout=PIPE,
                      stderr=PIPE
                      )
    osslPopen.stdin.write(sslpwdsb)
    osslPopen.stdin.close()

    errcode = osslPopen.wait()
    if errcode != 0:
        raise Pkcs11Exception(f"Error running openssl exit code: {errcode}")


conn.free_pkcs11()
