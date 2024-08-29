#!/usr/bin/python3.11

import pyximport

pyximport.install()
from PyPkcs11 import dumpBuf

from PyPkcs11 import CKA_CLASS
from PyPkcs11 import CKA_ID
from PyPkcs11 import CKA_KEY_TYPE
from PyPkcs11 import CKA_TOKEN
from PyPkcs11 import CKA_PRIVATE
from PyPkcs11 import CKA_GOSTR3410_PARAMS
from PyPkcs11 import CKA_GOSTR3411_PARAMS

from PyPkcs11 import Pkcs11Connection

conn = Pkcs11Connection("/usr/lib64/librtpkcs11ecp.so")

conn.fill_slots_list()

print("Slots list: ", conn.slots)

if len(conn.slots) == 0:
    quit()

conn.fill_mechanism_list()

print("Mech list: ", "\n".join(conn.mechanisms))

#conn.format_token("87654321", "12345678", "myVlRutoken")

if conn.slots == 0:
    quit(2)

conn.open_session(0)

conn.login("12345678")

conn.gen_key_symm()

conn.free_pkcs11()

quit()

keyPairID = "GOST R 34.10-2012 (256 bits) sample key pair ID (Aktiv Co.)"
keyTypes = {
    "CKK_GOSTR3410": 0x00000030,
    "CKK_GOSTR3411": 0x00000031,
    "CKK_GOST28147": 0x00000032
}
ckoTypes = {
    "CKO_DATA ": 0x00000000,
    "CKO_CERTIFICATE": 0x00000001,
    "CKO_PUBLIC_KEY": 0x00000002,
    "CKO_PRIVATE_KEY": 0x00000003,
    "CKO_SECRET_KEY": 0x00000004,
    "CKO_HW_FEATURE": 0x00000005,
    "CKO_DOMAIN_PARAMETERS": 0x00000006,
    "CKO_MECHANISM": 0x00000007,
    "CKO_OTP_KEY": 0x00000008,
    "CKO_VENDOR_DEFINED": 0x80000000
}

parametersR3410_2012_256 = [0x06, 0x07, 0x2a, 0x85, 0x03, 0x02, 0x02, 0x23, 0x01]
parametersR3411_2012_256 = [0x06, 0x08, 0x2a, 0x85, 0x03, 0x07, 0x01, 0x01, 0x02, 0x02]
attributes = [["CKA_CLASS", 0x00000002],
              ["CKA_ID", "GOST R 34.10-2012 (256 bits) sample key pair ID (Aktiv Co.)"],
              ["CKA_KEY_TYPE", keyTypes["CKK_GOSTR3410"]],
              ["CKA_TOKEN", True],
              ["CKA_PRIVATE", False, True],
              ["CKA_GOSTR3410_PARAMS", "0x06, 0x07, 0x2a, 0x85, 0x03, 0x02, 0x02, 0x23, 0x01"],
              ["CKA_GOSTR3411_PARAMS", "0x06, 0x08, 0x2a, 0x85, 0x03, 0x07, 0x01, 0x01, 0x02, 0x02"]]

template = [CKA_CLASS(ckoTypes["CKO_PUBLIC_KEY"]),
            CKA_ID("GOST R 34.10-2012 (256 bits) sample key pair ID (Aktiv Co.)"),
            CKA_KEY_TYPE(keyTypes["CKK_GOSTR3410"]),
            CKA_TOKEN(True),
            CKA_PRIVATE(False),
            CKA_GOSTR3410_PARAMS("0x06 0x07 0x2a 0x85 0x03 0x02 0x02 0x23 0x01"),
            CKA_GOSTR3411_PARAMS("0x06 0x08 0x2a 0x85 0x03 0x07 0x01 0x01 0x02 0x02")
            ]

ca = CK_ATTRIB()
breakpoint()
print(template[0].ret(ca.retPtr()))
print(ca.retData())

if len(conn.slots) == 0:
    print("Токена нет")

else:
    pin = 12345678
    rv4 = conn.gen_key_pair(pin,
                            keyPairID,
                            keyTypes["CKK_GOSTR3410"],
                            parametersR3410_2012_256,
                            parametersR3411_2012_256,
                            template)

# rvs2 = PyPkcs11.format_token(slotsList,functionListExUIP)
# pin = 12345678
# rvs3 = PyPkcs11.mechanism_list(slotsList,functionListUIP)
# for m in rvs3:
#     print(m)
conn.free_pkcs11()
