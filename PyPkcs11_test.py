#!/usr/bin/python3
import PyPkcs11
from PyPkcs11 import CKA_CLASS
from PyPkcs11 import CKA_ID
from PyPkcs11 import CKA_KEY_TYPE
from PyPkcs11 import CKA_TOKEN
from PyPkcs11 import CKA_PRIVATE
from PyPkcs11 import CKA_GOSTR3410_PARAMS
from PyPkcs11 import CKA_GOSTR3411_PARAMS

functionListUIP, functionListExUIP = PyPkcs11.init_pkcs11("./librtpkcs11ecp.so")
# print(functionListUIP)

slotsList = PyPkcs11.get_slots_list(functionListUIP)
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

Templates = [CKA_CLASS(ckoTypes["CKO_PUBLIC_KEY"], ckoTypes["CKO_PRIVATE_KEY"]),
             CKA_ID("GOST R 34.10-2012 (256 bits) sample key pair ID (Aktiv Co.)"),
             CKA_KEY_TYPE(keyTypes["CKK_GOSTR3410"]),
             CKA_TOKEN(True),
             CKA_PRIVATE(False, True),
             CKA_GOSTR3410_PARAMS("0x06 0x07 0x2a 0x85 0x03 0x02 0x02 0x23 0x01"),
             CKA_GOSTR3411_PARAMS("0x06 0x08 0x2a 0x85 0x03 0x07 0x01 0x01 0x02 0x02")
             ]

if slotsList == 0:
    print("Токена нет")

else:
    pin = 12345678
    rv4 = PyPkcs11.gen_key_pair(slotsList, pin, functionListUIP, keyPairID, keyTypes["CKK_GOSTR3410"],
                                parametersR3410_2012_256, parametersR3411_2012_256, Templates)

# rvs2 = PyPkcs11.format_token(slotsList,functionListExUIP)
# pin = 12345678
# rvs3 = PyPkcs11.mechanism_list(slotsList,functionListUIP)
# for m in rvs3:
#     print(m)
