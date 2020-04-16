package org.irisa.scp10;

import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.Util;

public class CRTJC extends TLVParserJC {
    public static final short MAX_CRT_SIZE = 44;

    /* Supported tags */
    public static final short MAC_TAG = (short) 0x00B4;
    public static final short ENC_TAG = (short) 0x00B8;
    public static final short KEY_USAGE_TAG = (short) 0x0095;
    public static final short KEY_TAG = (short) 0x00D1;
    public static final short IV_TAG = (short) 0x0091;

    /* Static getters */
    public static short getCRT(byte[] crt, short crtOff, byte[] out, short outOff) {
        short len = getCRTLen(crt, crtOff);
        return (short) (Util.arrayCopy(crt, crtOff, out, outOff, len) - outOff);
    }

    public static short getCRTLen(byte[] crt, short crtOff) {
        short len = (short) (crt[(short) (crtOff+1)]);
        if ( crt[crtOff] != (byte) MAC_TAG && crt[crtOff] != (byte) ENC_TAG) {
            ISOException.throwIt(ISO7816.SW_DATA_INVALID);
        }
        if (len > 128)
            ISOException.throwIt(ISO7816.SW_DATA_INVALID);
        // Return the length of the field plus two for the tag and length bytes
        return (short) (len + 2);
    }

    public static short getTag(byte[] crt, short crtOff) {
        if (crt[crtOff] != MAC_TAG && crt[crtOff] != ENC_TAG)
            ISOException.throwIt(ISO7816.SW_DATA_INVALID);
        return crt[crtOff];
    }

    public static short getUsage(byte[] crt, short crtOff) {
        short off = getElementOffset(crt, crtOff, MAX_CRT_SIZE, KEY_USAGE_TAG);
        return crt[(short) (off + 2)];
    }

    public static short getKey(byte[] crt, short crtOff, byte[] out, short outOff) {
        short crtLen = getCRTLen(crt, crtOff);
        return getElement(crt, crtOff, crtLen, out, outOff, KEY_TAG);
    }

    public short getIv(byte[] crt, short crtOff, byte[] out, short outOff) {
        short crtLen = getCRTLen(crt, crtOff);
        return getElement(crt, crtOff, crtLen, out, outOff, IV_TAG);
    }
}