#!/usr/bin/env python3
from smartcard.sw.SWExceptions import SWException
from smartcard.util import toHexString
from Client.scp10Client import SCP10Client
from Client.crt import CRT

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


clientKey_enc = read_as_tuple("_data/oce_enc.key")
clientCert_enc = read_as_hex("_data/oce_enc.cvc")
clientKey_sig = read_as_tuple("_data/oce_sig.key")
clientCert_sig = read_as_hex("_data/oce_sig.cvc")

tp_key = read_as_tuple("_data/trust_point.key")
tp_cert = read_as_hex("_data/trust_point.cvc")

CRT_MAC = 0xB4
CRT_ENC = 0xB8

AID = [0xD0, 0xD1, 0xD2, 0xD3, 0xD4, 0xD5, 0x02, 0x01]
mutual_auth = True
key_transport = False
card_cert_verif = True
debug = False
nb_crts = 2

vulnerable = True

try:
    legitimate_client = SCP10Client(clientKey_enc, clientCert_enc, clientKey_sig, clientCert_sig, tp_key, tp_cert, key_transport=key_transport,
                                    mutual_auth=mutual_auth, cert_verif=card_cert_verif, debug=debug, chan=1)
    legitimate_client.select(AID)
    legitimate_client.manage_security_env()
    legitimate_client.send_cert('enc')
    legitimate_client.send_cert('sig')
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
        if i < len(legitimate_client.session_ivs):
            print("\t[+] IV ", i, ": ", toHexString(legitimate_client.session_ivs[i]))
        else:
            print("\t[+] No IV (default to 00 ... 00)")
        print("")

except (SWException, ValueError) as e:
    print(e)
