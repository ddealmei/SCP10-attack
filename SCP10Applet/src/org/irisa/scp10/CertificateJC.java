package org.irisa.scp10;

import javacard.framework.Util;

public class CertificateJC extends TLVParserJC{
    /* Supported tags */
    static final short CVC_TAG = 0x7F21;
    static final short CVC_BODY_TAG = 0x7F4E;
    static final short ISSUER_REF_TAG = 0x42;
    static final short PUBLIC_KEY_TAG = 0x7F49;
    static final short MODULUS_TAG = 0x81;
    static final short E_TAG = 0x82;
    static final short HOLDER_REF_TAG = 0x5F20;
    static final short SIGNATURE_TAG = 0x5F37;

    public static short getSignature(byte[] cert, short certOff, short certLen, byte[] buff, short bOff) {
        return getElement(cert, certOff, certLen, buff, bOff, SIGNATURE_TAG);
    }

    public static short getCertificateBody(byte[] cert, short certOff, short certLen, byte[] buff, short bOff) {
        return getElement(cert, certOff, certLen, buff, bOff, CVC_BODY_TAG);
    }

    public static short getHolderRef(byte[] cert, short certOff, short certLen, byte[] buff, short bOff) {
        return getElement(cert, certOff, certLen, buff, bOff, HOLDER_REF_TAG);
    }

    public static short getIssuerRef(byte[] cert, short certOff, short certLen, byte[] buff, short bOff) {
        return getElement(cert, certOff, certLen, buff, bOff, ISSUER_REF_TAG);
    }

    public static void setRSAPublicKey(byte[] cert, short certOff, short certLen, RSAKeyHolderJC rsa) {
        short eOff = getElementOffset(cert, certOff, certLen, E_TAG);
        eOff += ( (E_TAG & (short) 0xFF00) == 0) ? 1 : 2;
        short eLen = getLength(cert, eOff);
        eOff++;     // e is never more than 128 bytes

        short nOff = getElementOffset(cert, certOff, certLen, MODULUS_TAG);
        nOff += ( (MODULUS_TAG & (short) 0xFF00) == 0) ? 1 : 2;
        short nLen = getLength(cert, nOff);
        nOff += 2;     // n is always between 128 and 256 bytes long

        rsa.setPublicKey(cert, eOff, eLen, nOff, nLen);
    }

    public static short encodeCVC(byte[] cert, short certOff, short certLen, byte[] buff, short bOff) {
        short i = bOff;

        Util.setShort(buff, i, CVC_TAG);
        i += 2;

        if (certLen > 256) {
            buff[i++] = (byte) 0x82;
            Util.setShort(buff, i, certLen);
            i += 2;
        }
        else if (certLen > 128) {
            buff[i++] = (byte) 0x81;
            buff[i++] = (byte) certLen;
        }
        else {
            buff[i++] = (byte) certLen;
        }

        Util.arrayCopy(cert, certOff, buff, i, certLen);
        i += certLen;

        return (short) (i-bOff);
    }
}
