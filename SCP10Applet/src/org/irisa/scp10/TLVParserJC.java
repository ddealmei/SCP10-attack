package org.irisa.scp10;

import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.Util;

public class TLVParserJC {

    private static boolean isNestedStructure(short tag) {
        // If bit 5 is set, it means we have a nested structure
        if (tag >= 256)
            return (tag & 0x2000) == 0x2000;
        else
            return (tag & 0x0020) == 0x0020;
    }

    /**
     * Return the DER tag present in buffer at offset bOff.
     * @param buff
     *      Buffer containing the tag.
     * @param bOff
     *      Offset of the tag in buffer.
     * @return
     *      A short representing the tag.
     */
    private static short getTag(byte[] buff, short bOff) {
        if ((buff[bOff] & 0x0F) == 0x0F)
            return Util.makeShort(buff[bOff], buff[(short) (bOff+1)]);
        else
            return (short) (buff[bOff] & 0xFF);
    }

    /**
     * Return the length of the field present in buffer at offset bOff.
     * @param buff
     *      Buffer containing the field.
     * @param bOff
     *      Offset of the length in buffer.
     * @return
     *      A short representing the length.
     */
    public static short getLength(byte[] buff, short bOff) {
        switch (buff[bOff]) {
            case (byte) 0x81:
                return (short) (buff[(short) (bOff+1)] & 0xFF);
            case (byte) 0x82:
                return Util.getShort(buff, (short) (bOff+1));
            default:
                return (short) (buff[bOff] & 0xFF);
        }
    }

    /**
     * Look for the offset of an element in buff.
     * @param buff
     *      Intput buffer, containing the element we look for.
     * @param bOff
     *      Offset from which the search will begin.
     * @param bLen
     *      Length of the input buffer.
     * @param tagElt
     *      Tag of the element we look for.
     * @return
     *      The offset of the tag we are looking for. Be careful to remove the tag and the size before processing data
     */
    public static short getElementOffset(byte[] buff, short bOff, short bLen, short tagElt) {
        short len;
        short tag = 0;
        short i = bOff;
        while (i < (short) (bLen+bOff-2)) {
            // Get the current tag
            tag = getTag(buff, i);
            // If the tag correspond to the offset, we are done
            if (tag == tagElt) {
                return i;
            }

            // Increment the offset according to the tag' size
            boolean short_tag = (tag & (short) 0xFF00) == 0;
            i += short_tag ? 1 : 2;
            // Get the length and increment the offset according to its size
            len = getLength(buff, i);
            if (len >= 0x80){
                i++;
                if (len > 0xFF)
                    i++;
            }
            i++;

            if (isNestedStructure(tag)) {
                i = getElementOffset(buff, i, bLen, tagElt);
            }
            // Otherwise, skip the data
            else {
                i += len;
            }
        }

        ISOException.throwIt(ISO7816.SW_DATA_INVALID);

        return 0;   // Never happens, but needed for compilation
    }

    /**
     * Look for an element in buffIn, and copy it in buffOut.
     * @param buffIn
     *      Intput buffer, containing the element we look for.
     * @param bInOff
     *      Offset from which the search will begin.
     * @param bInLen
     *      Length of the input buffer.
     * @param buffOut
     *      Buffer in which the element will be copied.
     * @param bOutOff
     *      Offset at which the element will be copied in buffOut.
     * @param tagElt
     *      Tag of the element we look for.
     * @return
     *      The length of the element we got.
     */
    public static short getElement(byte[] buffIn, short bInOff, short bInLen, byte[] buffOut, short bOutOff, short tagElt) {
        short eltOff = getElementOffset(buffIn, bInOff, bInLen, tagElt);
        eltOff += ( (tagElt & (short) 0xFF00) == 0) ? 1 : 2;
        // Get the length and increment the offset according to its size
        short len = getLength(buffIn, eltOff);
        if (len >= 0x80){
            eltOff++;
            if (len > 0xFF)
                eltOff++;
        }
        eltOff++;

        Util.arrayCopy(buffIn, eltOff, buffOut, bOutOff, len);

        return len;
    }

}
