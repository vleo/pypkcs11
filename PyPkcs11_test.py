#!/usr/bin/python3
import PyPkcs11

functionListUIP, functionListExUIP = PyPkcs11.init_pkcs11("./librtpkcs11ecp.so")
# print(functionListUIP)

slotsList = PyPkcs11.get_slots_list(functionListUIP)



# rvs2 = PyPkcs11.format_token(slotsList,functionListExUIP)
# pin = 12345678
# rvs3 = PyPkcs11.mechanism_list(slotsList,functionListUIP)
# for m in rvs3:
#     print(m)

pin = 12345678
rv4 = PyPkcs11.gen_key_pair(slotsList,pin,functionListUIP)


