#!/usr/bin/python3
import PyPkcs11

rvs = PyPkcs11.init_pkcs11("./librtpkcs11ecp.so")

rvs1 = PyPkcs11.get_slots_list()

rvs2 = PyPkcs11.format_token()
# #print("rvs: {}".format(rvs))

