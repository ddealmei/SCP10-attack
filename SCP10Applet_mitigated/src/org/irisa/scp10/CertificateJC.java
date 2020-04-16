package org.irisa.scp10;

public class CertificateJC extends TLVParserJC{
    /* Supported tags */
    static final short CVC_TAG = 0x7F21;
    static final short CVC_BODY_TAG = 0x7F4E;
    static final short ISSUER_REF_TAG = 0x42;
    static final short PUBLIC_KEY_TAG = 0x7F49;
    static final short MODULUS_TAG = 0x81;
    static final short E_TAG = 0x82;
    static final short HOLDER_REF_TAG = 0x5F20;
    static final short SIGNATURE_TAG = 0x9E;
    static final short KEY_USAGE_TAG = 0x5F4C;

    /* Different key usage */
    static final byte KU_ENC = 0x01;
    static final byte KU_SIG = 0x02;

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

    public static byte getKeyUsage(byte[] cert, short certOff, short certLen) {
        byte[] ku = new byte[1];
        getElement(cert, certOff, certLen, ku, (short) 0, KEY_USAGE_TAG);

        return (byte) (ku[0] & 0xFF);
    }
}
