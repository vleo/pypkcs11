#!/usr/bin/env python
import sys

from pypkcs11.PyPkcs11 import Pkcs11Exception, Pkcs11Connection
import argparse

from subprocess import Popen, PIPE
import os

import secrets

def initToken(conn, sortedSlots, sopin, pinArg, label):
    pin = []
    for s in sortedSlots:
        i = s[0]
        lbl = f"{label}{i:02d}"
        pin.append(pinArg if pinArg else input(f"Enter pin for rutoken with label={s[2]} i={s[0]}:"))
        conn.format_token(i, sopin, pin[-1], lbl)
    conn.open_sessions()
    for s in sortedSlots:
        i = s[0]
        serial = s[3]
        lbl = s[2]
        kuzId = f"kuz-{serial}"
        conn.login(i, pin[i])
        conn.gen_key_symm_kuznechik(i, kuzId)
        print(f"Created secret key for kuznechik with label={lbl} serial= {serial} kuzId= {kuzId}")


def prepareConnAndSlots():
    conn = Pkcs11Connection("/opt/aktivco/rutokenecp/x86_64/librtpkcs11ecp.so")

    conn.fill_slots_list()
    # conn.fill_mechanism_list()

    sortedSlots = sorted(
        [(v["six"], v["si"]["slotDescription"], v["ti"]["label"], v["ti"]["serialNumber"]) for v in conn.slots],
        key=lambda v: v[3])

    if len(sortedSlots) == 0:
        raise Pkcs11Exception(f"No rutokens found")

    print("Slots sorted by slot ID:")
    print("\n".join([str(v) for v in sortedSlots]))

    return conn, sortedSlots


def argsParse():
    ap: argparse.ArgumentParser = argparse.ArgumentParser()

    ap.add_argument("--inittoken", action="store_true")
    ap.add_argument("--sopin", action="store")
    ap.add_argument("--pin", action="store")
    ap.add_argument("--label", action="store")

    return ap.parse_args()


def main():
    try:
        cmdLineArgs_g: argparse.Namespace = argsParse()

        conn_g, sortedSlots_g = prepareConnAndSlots()

        if cmdLineArgs_g.inittoken:
            if not (cmdLineArgs_g.label and cmdLineArgs_g.sopin):
                raise Pkcs11Exception(f"Must specify --label, --sopin for --inittoken")
            initToken(conn_g, sortedSlots_g, cmdLineArgs_g.sopin, cmdLineArgs_g.pin, cmdLineArgs_g.label)

        conn_g.free_pkcs11()

    except Pkcs11Exception as p11e:
        print(f"Pkcs11 error: {p11e}", file=sys.stderr)
        exit(128)


if __name__ == '__main__':
    main()
