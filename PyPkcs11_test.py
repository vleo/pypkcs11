#!/usr/bin/python3
import PyPkcs11

functionListUIP = PyPkcs11.init_pkcs11("./librtpkcs11ecp.so")
print(functionListUIP)

slotsList = PyPkcs11.get_slots_list(functionListUIP)



# rvs2 = PyPkcs11.format_token()
pin = 12345678
rvs3 = PyPkcs11.mechanism_list(pin,slotsList,functionListUIP)
for m in rvs3:
    print(m)
#print(rvs3)
# #print("rvs: {}".format(rvs))

