package org.irisa.scp10;

public class Utils {
    static public byte[] RSA_EXPONENT = {0x03};
    static public short RSA_MODULUS_SIZE = 1024;

    /**
     * Compute the subtraction of two byte array, with carry. The numbers to
     * subtract are expected to be the same size (same byte length)
     * @param buff
     *      Buffer containing the numbers
     * @param aOff
     *      Offset of the first number. We assume b < a.
     * @param bOff
     *      Offset of the second number
     * @param cOff
     *      Offset of the result
     * @param nLen
     *      Length of the numbers to subtract (in bytes)
     */
    public static void Subtract(byte[] buff, short aOff, short bOff, short cOff, short nLen) {
        boolean carry = false;
        short a = 0, b = 0;

        for (short i = (short) 0; i < nLen; i++) {
            a = carry ? (short) ((0xFF & buff[(short) (aOff+nLen-1-i)]) - 1) : (short) (0xFF & buff[(short) (aOff+nLen-1-i)]);
            b = (short) (0xFF & buff[(short) (bOff+nLen-1-i)]);

            carry = (a < b);
            buff[(short) (cOff+nLen-1-i)] = (byte) (carry ? (short) (a+256 - b) : (short) (a-b));
        }
    }

    /**
     * Compare the value of two big integers, represented as unsigned byte arrays.
     * Both integer are represented with the same number of bytes.
     * @param buff
     * @param aOff
     * @param bOff
     * @return
     *      A negative number if b > a
     *      0 if a == 0
     *      A positive number if a > b
     */
    public static short CompareConstantTime(byte[] buff, short aOff, short bOff) {
        short byteA, byteB;
        short aIsBigger = 0, bIsBigger = 0;
        short byteAIsBigger = 0, byteBIsBigger = 0;

        for(short i = 0; i < (short) (bOff - aOff); i++) {
            byteA = (short) (buff[(short) (aOff + i)] & 0xFF);
            byteB = (short) (buff[(short) (bOff + i)] & 0xFF);

            byteAIsBigger = (short) (((short) (byteB - byteA) >> 8) & 1);
            byteBIsBigger = (short) (((short) (byteA - byteB) >> 8) & 1);

            aIsBigger = (short) (aIsBigger | (byteAIsBigger & ~bIsBigger));
            bIsBigger = (short) (bIsBigger | (byteBIsBigger & ~aIsBigger));
        }

        return (short) (aIsBigger - bIsBigger);
    }

    /**
     * Compare two array
     * @param buffer
     * @param aOffset
     * @param bOffset
     * @param len
     * @return
     */
    public static boolean ArrayEqual(byte[] buffer, short aOffset, short bOffset, short len) {
        boolean isEqual = true;

        for (short i = 0; i < len; i++)
            isEqual &= (buffer[(short) (aOffset+i)] == buffer[(short) (bOffset+i)]);

        return isEqual;
    }
}
