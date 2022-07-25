#!/usr/bin/python3
import PyPkcs11

# rvs = PyPkcs11.init_pkcs11("./librtpkcs11ecp.so")
# #print("rvs: {}".format(rvs))

# rvs1 , rvs2 = PyPkcs11.get_slots_list()
#print("rvs: {}".format(rvs))

rvs1 = PyPkcs11.format_token()

# print(rvs1, rvs2)
