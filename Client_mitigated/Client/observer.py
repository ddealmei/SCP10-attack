from smartcard.CardConnectionObserver import ConsoleCardConnectionObserver
from smartcard.util import toHexString
import re


class SCP10Observer(ConsoleCardConnectionObserver):
    """ This observer will interpret various SCP10 ADPU and replace them with 
    a human readable string."""

    re_select = r"^\d{2} A4 \d{2} \d{2} \d{2}"
    re_get_response = r"^\d{2} C0"

    re_manage_sec_ext_certVerif = r"^\d{2} 22 81 B6 \d{2}"
    re_manage_sec_ext_noCertVerif = r"^\d{2} 22 81 A4 \d{2}"
    re_manage_sec_mut_certVerif = r"^\d{2} 22 C1 B6 \d{2}"
    re_manage_sec_mut_noCertVerif = r"^\d{2} 22 C1 A4 \d{2}"
    re_send_certs_verif = r"^\d{2} 2A 00 BE \d{2}"
    re_decrypt = r"^\d{2} 2A 80 84 \d{2}"
    re_get_certs = r"^\d{2} CA 7F 21 \d{2}"
    re_get_challenge = r"^\d{2} 84 00 00 \d{2}"
    re_external_auth = r"^\d{2} 82 00 00 \d{2}"
    re_internal_auth = r"^\d{2} 88 00 00 \d{2}"

    def update(self, cardconnection, ccevent):

        if 'connect' == ccevent.type:
            print('connecting to ' + cardconnection.getReader())

        elif 'disconnect' == ccevent.type:
            print('disconnecting from ' + cardconnection.getReader())

        elif 'command' == ccevent.type:
            s = toHexString(ccevent.args[0])
            s = re.sub(self.re_select, "SELECT:", s)
            s = re.sub(self.re_get_response, "GET MORE DATA", s)
            s = re.sub(self.re_manage_sec_ext_certVerif,
                       "MANAGE SECURITY ENVIRONNEMENT: External auth only - Cert verification card-side:", s)
            s = re.sub(self.re_manage_sec_ext_noCertVerif,
                       "MANAGE SECURITY ENVIRONNEMENT: External auth only - No cert verification card-side:", s)
            s = re.sub(self.re_manage_sec_mut_certVerif,
                       "MANAGE SECURITY ENVIRONNEMENT: Mutual authentication - Cert verification card-side:", s)
            s = re.sub(self.re_manage_sec_mut_noCertVerif,
                       "MANAGE SECURITY ENVIRONNEMENT: Mutual authentication - No cert verification card-side:", s)
            s = re.sub(self.re_send_certs_verif, "PERFORM SECURITY OPERATION - verify:", s)
            s = re.sub(self.re_decrypt, "PERFORM SECURITY OPERATION - decipher:", s)
            s = re.sub(self.re_get_certs, "GET DATA - certificates:", s)
            s = re.sub(self.re_get_challenge, "GET CHALLENGE", s)
            s = re.sub(self.re_external_auth, "EXTERNAL AUTHENTICATION:", s)
            s = re.sub(self.re_internal_auth, "INTERNAL AUTHENTICATION:", s)

            print('>>', s)

        elif 'response' == ccevent.type:
            if not ccevent.args[0]:
                if tuple(ccevent.args[-2:]) == (0x90, 00):
                    print("<< **SUCCESS**\n")
                else:
                    print('<<  []', "(%-2X %-2X)" % tuple(ccevent.args[-2:]), '\n')
            else:
                if tuple(ccevent.args[-2:]) == (0x90, 00):
                    print("<< **SUCCESS**", toHexString(ccevent.args[0]), '\n')
                else:
                    print('<<',
                          toHexString(ccevent.args[0]),
                          "(%-2X %-2X)" % tuple(ccevent.args[-2:]), '\n')
