# Card connection related
from smartcard.CardType import AnyCardType
from smartcard.CardRequest import CardRequest
from smartcard.util import BinStringToHexList
# Error checking
from smartcard.sw.ErrorCheckingChain import ErrorCheckingChain
from smartcard.sw.ISO7816_4ErrorChecker import ISO7816_4ErrorChecker

# Utils
from Crypto.Random import random
from Crypto.Hash import SHA as SHA1

# Local imports
from .helpers import *
from .cvc import CVCertificate
from .apdu import APDUCommand
from .observer import SCP10Observer
from .rsaKeyHolder import RsaKeyHolder


class SCP10Client(object):
    APDU_MAX_LENGTH = 255
    DEFAULT_CLA = 0x80

    SW_SUCCESS = (0x90, 0x00)
    SW_BYTES_REMAINING = (0x61, 0x00)

    @staticmethod
    def dump_hex(x):
        for b in x:
            h = hex(b).split('x')[1]
            if len(h) == 1:
                h = '0' + h
            print(h, end='')
        print("\n")

    def __init__(self, clientkey_enc, clientcert_enc, clientkey_sig, clientcert_sig, tp_key, tp_cert, key_transport=False, mutual_auth=True, cert_verif=True, debug=False, chan=0, vuln=True):
        self.vuln = vuln
        if chan > 3 or chan < 0:
            raise ValueError("Logical channel number must be in [0, 3]")
        self.cla = self.DEFAULT_CLA + chan

        self.security_lvl = 0x42  # ANY_AUTHENTICATED + C_DECRYPTION

        self.clientKey_enc = RsaKeyHolder(clientkey_enc)
        self.clientCert_enc = CVCertificate(clientcert_enc)
        self.clientKey_sig = RsaKeyHolder(clientkey_sig)
        self.clientCert_sig = CVCertificate(clientcert_sig)

        self.tp_key = RsaKeyHolder(tp_key)
        self.tp_cert = CVCertificate(tp_cert)

        self.cardKey_enc = None
        self.cardCert_enc = None
        self.cardKey_sig = None
        self.cardCert_sig = None

        self.key_transport = key_transport
        self.mutual_auth = mutual_auth
        self.cert_verif = cert_verif

        self.session_keys = []
        self.session_ivs = []
        self.client_secret = []
        self.card_secret = []

        # Wait for any card to be put on a reader, and initiate a connection
        card_type = AnyCardType()
        card_request = CardRequest(timeout=None, cardType=card_type)
        self.card = card_request.waitforcard()
        self.card.connection.connect()

        error_chain = []
        error_chain = [ErrorCheckingChain(error_chain, ISO7816_4ErrorChecker())]
        self.card.connection.setErrorCheckingChain(error_chain)
        # Set an observer for debugging
        if debug:
            observer = SCP10Observer()
            self.card.connection.addObserver(observer)

    def receive_response(self, apdu): 
        data = []

        # Get the response and copy the data part into the buffer
        response, sw1, sw2 = self.card.connection.transmit(apdu.buffer)
        data += response

        get_resp = APDUCommand(apdu.getCLA(), 0xC0, apdu.getP1(), apdu.getP2())
        # Recover all data until success or error
        while sw1 == self.SW_BYTES_REMAINING[0]:
            response, sw1, sw2 = self.card.connection.transmit(get_resp.buffer)
            data += response

        return data

    def send_command(self, cla, ins, p1, p2, data=[]):
        # Check if we need command chaining
        if len(data) > self.APDU_MAX_LENGTH:
            cla |= 0x10

        for i in range(0, len(data) - self.APDU_MAX_LENGTH, self.APDU_MAX_LENGTH):
            buffer = data[i:i+self.APDU_MAX_LENGTH]
            apdu = APDUCommand(cla, ins, p1, p2, buffer)
            self.card.connection.transmit(apdu.buffer)
    
        if (cla & 0x10) == 0x10:
            cla ^= 0x10

        remaining_bytes = len(data) % self.APDU_MAX_LENGTH

        buffer = data[-remaining_bytes:]
        apdu = APDUCommand(cla, ins, p1, p2, buffer)
        return self.receive_response(apdu)
    
    def select(self, applet_id):
        cla = (self.DEFAULT_CLA ^ self.cla)
        apdu = APDUCommand(cla, 0xA4, 0x04, 0x00, applet_id)
        self.card.connection.transmit(apdu.buffer)

    def manage_security_env(self):
        payload = [0x80, 0x10, 0x02]
        payload[2] = 0x01 if not self.key_transport else 0x02
        if self.mutual_auth:
            if self.cert_verif:
                self.send_command(self.cla, 0x22, 0xC1, 0xB6, payload)
            else:
                self.send_command(self.cla, 0x22, 0xC1, 0xA4, payload)
        else:
            if self.cert_verif:
                self.send_command(self.cla, 0x22, 0x81, 0xB6, payload)
            else:
                self.send_command(self.cla, 0x22, 0x81, 0xA4, payload)
    
    def send_cert(self, usage):
        if self.cert_verif:
            if usage == "enc":
                cert = self.clientCert_enc.get_encoded()
            elif usage == "sig":
                cert = self.clientCert_sig.get_encoded()
            else:
                raise ValueError("Unknown key usage")
            self.send_command(self.cla, 0x2A, 0x00, 0xBE, cert)
    
    def check_card_certificate(self):
        # Get the certificates from the card
        response = self.send_command(self.cla, 0xCA, 0x7F, 0x21)

        # Separate both certificate and check them
        cert1 = response[:CVCertificate.get_length(response, 2)+5]
        cert2 = response[len(cert1):]
        card_certs = [CVCertificate(cert1), CVCertificate(cert2)]

        for cert in card_certs:
            # Check certificate validity:
            #   * issued by Trust Point,
            #   * valid signature
            #   * key usage
            if cert.get_issuer_ref() != self.tp_cert.get_holder_ref():
                raise ValueError("Fail GET DATA - certificate: wrong issuer")
            body = cert.get_body()
            s = cert.get_signature()
            try:
                self.tp_key.verify_pkcs1(body, s)
            except ValueError:
                raise ValueError("Fail GET DATA - certificate: invalid signature")

            n, e = cert.get_pub()
            ku = cert.get_key_usage()[0]
            if ku & CVCertificate.KU_ENC == CVCertificate.KU_ENC:
                self.cardKey_enc = RsaKeyHolder((n, e))
                self.cardCert_enc = cert
            if ku & CVCertificate.KU_SIG == CVCertificate.KU_SIG:
                self.cardKey_sig = RsaKeyHolder((n, e))
                self.cardCert_sig = cert

    def send_encrypted_crt(self, crts=None, data=None):
        if data is None:
            # Prepare the payload
            payload = [0xD3, 0x01, self.security_lvl]
            for crt in crts:
                payload += crt.get_bytes()
            # Encrypt the payload using SD's public key
            buffer = self.cardKey_enc.encrypt_oaep(bytearray(payload))
        else:
            buffer = int_to_hex(data, self.clientKey_enc.size_bytes)

        # Send the encrypted payload
        self.send_command(self.cla, 0x2A, 0x80, 0x84, buffer)

        # To ease attacker interception
        return hex_to_int(buffer)
    
    def get_card_challenge(self):
        challenge = self.send_command(self.cla, 0x84, 0x00, 0x00)
        return challenge

    def external_authentication(self, challenge, crts):
        # Prepare the basic payload
        payload = [0xD3, 0x01, self.security_lvl]
        for crt in crts:
            payload += crt.get_bytes()
        
        if self.key_transport:
            payload += challenge
            buffer = self.clientKey_sig.sign_pkcs1(payload)
        else:
            # RandPad || payload || secretOCE is embedded in the signature
            self.client_secret = [random.getrandbits(8) for _ in range(32)]
            l = self.cardKey_sig.size_bytes - 32 - 22 - len(payload)
            to_embed = [random.getrandbits(8) for _ in range(l)] + payload 
            to_embed += self.client_secret
            # additional data are used in the signature process
            ad = challenge + self.cardCert_sig.get_holder_ref()

            buffer = self.clientKey_sig.sign_with_message_recovery(to_embed, ad)
            buffer = self.cardKey_enc.public_key_op(buffer)

        self.send_command(self.cla, 0x82, 0x00, 0x00, buffer)

    def internal_authentication(self, crts):
        if self.key_transport and not self.mutual_auth:
            return
        challenge_len = 16 if self.key_transport else 8
        challenge = [random.getrandbits(8) for _ in range(challenge_len)]

        payload = challenge + self.clientCert_sig.get_holder_ref()
        response = self.send_command(self.cla, 0x88, 0x00, 0x00, payload)

        if self.key_transport:
            to_hash = []
            for crt in crts:
                to_hash += crt.get_key()
            to_hash += challenge
            try:
                self.cardKey_sig.verify_pkcs1(to_hash, response)
            except ValueError:
                raise ValueError("Fail INTERNAL_AUTH: incorrect signature.")
        else:
            signature = self.clientKey_enc.private_key_op(response)
            ad = payload
            valid, recovered_data = self.cardKey_sig.verify_with_message_recovery(signature, ad)
            if not valid:
                raise ValueError("Fail INTERNAL_AUTH: incorrect signature.")
            secret_offset = self.cardKey_sig.size_bytes - 22 - 32
            self.card_secret = recovered_data[-secret_offset:]
        
    def key_derivation(self, crts):
        if self.key_transport:
            for crt in crts:
                self.session_keys.append(crt.get_key())
                self.session_ivs.append(crt.get_iv())
        else:
            buffer = [self.card_secret[i] ^ self.client_secret[i] for i in range(32)]
            buffer += [0 for _ in range(32)]

            for crt in crts:
                # This implementation only supports one MAC and one ENC key.
                if crt.get_bytes()[0] == 0xB4:
                    buffer[-1] = 1
                    self.session_ivs.append(self.card_secret[-4:] + self.client_secret[-4:])
                else:
                    buffer[-1] = 2
                key = SHA1.new(bytearray(buffer)).digest()[:16]
                self.session_keys.append(bytes_to_hex(key))

