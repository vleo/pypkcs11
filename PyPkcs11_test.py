#!/usr/bin/python3
import PyPkcs11

functionListUIP = PyPkcs11.init_pkcs11("./librtpkcs11ecp.so")

slotsUIP = PyPkcs11.get_slots_list(functionListUIP)

quit()

# rvs2 = PyPkcs11.format_token()
pin = 12345678
rvs3 = PyPkcs11.mechanism_list(pin)
print(rvs3)
# #print("rvs: {}".format(rvs))

